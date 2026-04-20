use super::handler::RequestContext;
use super::response::*;
use crate::state::{AppState, AttackLog, WafRule};
use chrono::Local;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Response, StatusCode};
use std::sync::Arc;
/// Stage 0: 低级自动化脚本嗅探 (User-Agent 检查)
pub fn is_bot(ctx: &RequestContext) -> bool {
    ctx.user_agent.is_empty()
        || ctx.user_agent.contains("curl")
        || ctx.user_agent.contains("python")
        || ctx.user_agent.contains("go-http-client")
}

/// Stage 0.5: Cookie/Token 令牌验证 + 指纹绑定检测
pub async fn verify_token(ctx: &RequestContext, state: &AppState) -> bool {
    let cookie_header = match ctx.raw_headers.get(hyper::header::COOKIE) {
        Some(v) => v,
        None => return false,
    };
    let cookie_str = match cookie_header.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };

    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("waf_clearance=") {
            if let Some(original_fp) = state.verified_tokens.read().await.get(token) {
                if original_fp.ip == ctx.ip && original_fp.user_agent == ctx.user_agent {
                    return true;
                } else {
                    // IP 或 UA 发生变化，失效旧令牌，强制重新质询
                    println!(
                        "⚠️ 环境变化，令牌失效！\n   Token: {}\n   原始环境 -> IP: {}, UA: {}\n   当前环境 -> IP: {}, UA: {}",
                        token, original_fp.ip, original_fp.user_agent, ctx.ip, ctx.user_agent
                    );
                    state.verified_tokens.write().await.invalidate(token);
                }
            }
            break;
        }
    }
    false
}

/// Stage 0.9: 质询死锁检测
/// 返回 Some(response) 表示用户仍在质询中，应拦截
pub async fn check_deadlock(
    ctx: &RequestContext,
    is_verified: bool,
    state: &AppState,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    if is_verified {
        return None;
    }
    let (n1, n2) = state.captcha_answers.read().await.get(&ctx.ip)?;
    if n1 == 0 && n2 == 0 {
        println!("🤖 IP {} 仍处于 [JS 质询死锁] 状态，强制拦截", ctx.ip);
        let html = render_js_challenge_page(&ctx.ip, &ctx.target_url);
        Some(create_response(html, StatusCode::SERVICE_UNAVAILABLE).unwrap())
    } else {
        println!("🤖 IP {} 仍处于 [数学题死锁] 状态，继续显示验证码", ctx.ip);
        let html = render_captcha_page(&ctx.ip, n1, n2, &ctx.target_url);
        Some(create_response(html, StatusCode::TOO_MANY_REQUESTS).unwrap())
    }
}

/// Stage 1: 惩罚盒子检查
pub async fn check_penalty(
    ctx: &RequestContext,
    state: &AppState,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    let current_penalty = state.penalty_box.read().await.get(&ctx.ip).unwrap_or(0);
    println!("🤖 IP {} 当前惩罚分：{}", ctx.ip, current_penalty);

    let ban_score = state.settings.read().await.penalty_ban_score;
    if current_penalty >= ban_score {
        let custom_page = state.custom_block_page.read().await.clone();
        let html = render_error_page(
            Some(&custom_page),
            403,
            "ACCESS DENIED",
            "您的 IP 因存在严重或频繁的恶意扫描行为，已被防御矩阵自动拉入黑名单。",
            "#ff0033",
            &ctx.ip,
        );
        Some(create_response(html, StatusCode::FORBIDDEN).unwrap())
    } else {
        None
    }
}

/// Stage 2: 高频 CC 攻击限流
/// 返回 None 表示未触发限流或已通过验证
pub async fn check_rate_limit(
    ctx: &RequestContext,
    is_verified: bool,
    state: &AppState,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    let count = state.rate_limiter.read().await.get(&ctx.ip).unwrap_or(0) + 1;
    state.rate_limiter.write().await.insert(ctx.ip.clone(), count);

    let threshold = state.settings.read().await.rate_limit_threshold as u64;
    if count <= threshold || is_verified {
        return None;
    }

    // 基于超出阈值的次数交替触发 JS 质询 / 数学题质询
    // 保证首次触发一定优先无感 JS 质询 (over_count = 1)
    let over_count = count - threshold;
    if over_count % 2 != 0 {
        // 路线 A: JS 无感质询
        println!("🤖 频率异常，触发 [JS 质询]: IP {}", ctx.ip);
        state.captcha_answers.write().await.insert(ctx.ip.clone(), (0, 0));
        let html = render_js_challenge_page(&ctx.ip, &ctx.target_url);
        Some(create_response(html, StatusCode::TOO_MANY_REQUESTS).unwrap())
    } else {
        // 路线 B: 数学题质询
        println!("🤖 频率异常，触发 [数学题质询]: IP {}", ctx.ip);
        let nanos = chrono::Utc::now().timestamp_subsec_nanos();
        let num1 = ((nanos / 1000) % 10) + 1;
        let num2 = ((nanos / 100000) % 10) + 1;
        state.captcha_answers.write().await.insert(ctx.ip.clone(), (num1, num2));
        let html = render_captcha_page(&ctx.ip, num1, num2, &ctx.target_url);
        Some(create_response(html, StatusCode::TOO_MANY_REQUESTS).unwrap())
    }
}

/// Stage 4.5: 路由级限流（在路由匹配后、代理转发前检查）
/// 使用独立 cache key `route:{prefix}:{ip}` 避免与全局限流冲突
pub async fn check_route_rate_limit(
    ctx: &RequestContext,
    state: &AppState,
    route_threshold: i32,
    route_prefix: &str,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    let key = format!("route:{}:{}", route_prefix, ctx.ip);
    let count = state.rate_limiter.read().await.get(&key).unwrap_or(0) + 1;
    state.rate_limiter.write().await.insert(key, count);

    if count <= route_threshold as u64 {
        return None;
    }

    println!("🚦 路由级限流触发: IP {} -> {} (QPS {}/{})", ctx.ip, route_prefix, count, route_threshold);
    let custom_page = state.custom_block_page.read().await.clone();
    let html = render_error_page(
        Some(&custom_page),
        429,
        "RATE LIMITED",
        &format!("您对路径 {} 的访问频率超过了该服务的限制，请稍后重试。", route_prefix),
        "#fa8c16",
        &ctx.ip,
    );
    Some(create_response(html, StatusCode::TOO_MANY_REQUESTS).unwrap())
}

// ─── URL 多层解码归一化 ────────────────────────────────────────────────────────

/// 递归 URL decode，最多解码 max_rounds 层，防止 %2527 → %27 → ' 类绕过
fn url_decode_normalize(input: &str, max_rounds: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..max_rounds {
        let decoded = percent_decode_str(&current);
        if decoded == current {
            break; // 没有更多编码可解
        }
        current = decoded;
    }
    current
}

/// 简单的 percent decode 实现（处理 %XX 和 +）
fn percent_decode_str(input: &str) -> String {
    let mut res = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                res.push(byte as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            res.push(' ');
        } else {
            res.push(bytes[i] as char);
        }
        i += 1;
    }
    res
}

// ─── Cookie 解析 ───────────────────────────────────────────────────────────────

/// 从请求头中提取所有 Cookie 的 value，组合为待匹配字符串列表
fn extract_cookie_values(ctx: &RequestContext) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(cookie_header) = ctx.raw_headers.get(hyper::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for pair in cookie_str.split(';') {
                let pair = pair.trim();
                if let Some((_key, value)) = pair.split_once('=') {
                    values.push(value.to_string());
                }
            }
        }
    }
    values
}

// ─── JSON Body 递归提取 ────────────────────────────────────────────────────────

/// 递归提取 JSON 中所有字符串值，用于字段级检测
fn extract_json_strings(val: &serde_json::Value, out: &mut Vec<String>) {
    match val {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_json_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map {
                extract_json_strings(v, out);
            }
        }
        _ => {}
    }
}

/// 辅助匹配函数
fn match_rule_logic(rule: &WafRule, target: &str) -> bool {
    let trg = target.to_lowercase(); // contains & exact 通常忽略大小写比较直观
    match rule.match_type.as_str() {
        "Exact" => trg == rule.keyword.to_lowercase(),
        "Regex" => {
            if let Some(re) = &rule.compiled_regex {
                re.is_match(target) // 正则保留原始大小写，给正则本身留出灵活性 (?i)
            } else {
                false
            }
        }
        _ => trg.contains(&rule.keyword.to_lowercase()), // 默认 Contains
    }
}

/// WAF 规则命中结果
pub struct WafRuleHit {
    /// 被拦截的响应 (action=Block 时有值, action=Log 时为 None)
    pub response: Option<Response<Either<Incoming, Full<Bytes>>>>,
    /// 命中的规则关键词
    pub matched_rule: String,
    /// 执行动作: "Block" 或 "Log"
    pub action: String,
}

/// Stage 3: WAF 关键词规则匹配
/// 返回 None 表示未命中规则（安全请求）
pub async fn check_waf_rules(
    ctx: &RequestContext,
    state: &AppState,
) -> Option<WafRuleHit> {
    let rules = state.rules.read().await;
    let mut hit_rule: Option<(String, String, Arc<std::sync::atomic::AtomicU64>)> = None; // (keyword, action, hit_counter)

    // 预处理：URL 多层解码归一化（最多 3 层）
    let decoded_path_query = url_decode_normalize(&ctx.path_query, 3);

    for rule in rules.iter() {
        // 跳过已停用的规则
        if rule.status != 1 {
            continue;
        }
        let is_hit = match rule.target_field.as_str() {
            "URL" => {
                // 同时匹配原始 URL 和解码后的 URL
                match_rule_logic(rule, &ctx.path_query)
                    || match_rule_logic(rule, &decoded_path_query)
            }
            "User-Agent" => match_rule_logic(rule, &ctx.user_agent),
            "Header" => {
                let mut hit = false;
                for (k, v) in ctx.raw_headers.iter() {
                    let combined = format!("{}: {:?}", k, v);
                    if match_rule_logic(rule, &combined) {
                        hit = true;
                        break;
                    }
                }
                hit
            }
            "Cookie" => {
                let cookie_values = extract_cookie_values(ctx);
                let mut hit = false;
                for val in &cookie_values {
                    let decoded_val = url_decode_normalize(val, 3);
                    if match_rule_logic(rule, val) || match_rule_logic(rule, &decoded_val) {
                        hit = true;
                        break;
                    }
                }
                hit
            }
            "Body" => {
                if let Some(ref b) = ctx.body_bytes {
                    let body_str = String::from_utf8_lossy(b);
                    let decoded_body = url_decode_normalize(&body_str, 3);

                    // 尝试 JSON 字段级解析
                    let content_type = ctx.raw_headers
                        .get(hyper::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if content_type.contains("application/json") {
                        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&body_str) {
                            let mut all_strings = Vec::new();
                            extract_json_strings(&json_val, &mut all_strings);
                            let mut json_hit = false;
                            for s in &all_strings {
                                let decoded_s = url_decode_normalize(s, 3);
                                if match_rule_logic(rule, s) || match_rule_logic(rule, &decoded_s) {
                                    json_hit = true;
                                    break;
                                }
                            }
                            json_hit
                        } else {
                            // JSON 解析失败，降级为原始匹配
                            match_rule_logic(rule, &body_str) || match_rule_logic(rule, &decoded_body)
                        }
                    } else {
                        // 非 JSON Body：原始匹配 + 解码后匹配
                        match_rule_logic(rule, &body_str) || match_rule_logic(rule, &decoded_body)
                    }
                } else {
                    false
                }
            }
            _ => {
                // 默认降级匹配 URL（含解码后）
                match_rule_logic(rule, &ctx.path_query)
                    || match_rule_logic(rule, &decoded_path_query)
            }
        };

        if is_hit {
            rule.increment_hit();
            hit_rule = Some((rule.keyword.clone(), rule.action.clone(), rule.hit_count.clone()));
            break;
        }
    }
    drop(rules);

    let (hit_rule_keyword, action, _) = match hit_rule {
        Some(v) => v,
        None => return None,
    };

    // 惩罚（Log 模式下减半惩罚，Block 模式全额惩罚）
    let current_penalty = state.penalty_box.read().await.get(&ctx.ip).unwrap_or(0);
    let attack_score = state.settings.read().await.penalty_attack_score;
    let penalty_increment = if action == "Log" { attack_score / 2 } else { attack_score };
    let new_penalty = current_penalty + penalty_increment;
    state.penalty_box.write().await.insert(ctx.ip.clone(), new_penalty);

    // 自动封禁持久化：惩罚分达阈值时写入 ip_blacklist 表
    let ban_score = state.settings.read().await.penalty_ban_score;
    if new_penalty >= ban_score {
        // 检查是否已在黑名单中（避免重复写入）
        let already_banned = state.ip_blacklist.read().await.contains(&ctx.ip);
        if !already_banned {
            let reason = format!("WAF 自动封禁: 惩罚分 {}/{}, 触发规则: {}", new_penalty, ban_score, hit_rule_keyword);
            let _ = sqlx::query("INSERT IGNORE INTO ip_blacklist (ip_address, reason) VALUES (?, ?)")
                .bind(&ctx.ip)
                .bind(&reason)
                .execute(&state.db_pool)
                .await;
            state.ip_blacklist.write().await.insert(ctx.ip.clone());
            println!(
                "🔒 IP {} 已被自动加入持久黑名单！惩罚分: {}/{}, 触发规则: {}",
                ctx.ip, new_penalty, ban_score, hit_rule_keyword
            );
        }
    }

    let log_action = if action == "Log" { "LOG_ONLY" } else { "BLOCKED" };
    println!(
        "{}  IP: {}, 惩罚分: {}/{}, 规则: {}, 动作: {}",
        if action == "Log" { "📝 记录攻击" } else { "❌ 拦截攻击！" },
        ctx.ip, new_penalty, ban_score, hit_rule_keyword, log_action
    );

    let log = AttackLog {
        time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        ip: ctx.ip_addr,
        path: ctx.path_query.clone(),
        matched_rule: hit_rule_keyword.clone(),
        action: log_action.to_string(),
    };
    let _ = state.log_tx.send(log).await;

    if action == "Log" {
        // 仅记录模式：不返回拦截响应，请求继续通行
        Some(WafRuleHit {
            response: None,
            matched_rule: hit_rule_keyword,
            action: "Log".to_string(),
        })
    } else {
        // 拦截模式：返回 403
        let custom_page = state.custom_block_page.read().await.clone();
        let html = render_error_page(
            Some(&custom_page),
            403,
            "REQUEST BLOCKED",
            "网关检测到您的请求中包含非法的参数或恶意代码特征，请求已被截断。",
            "#ff3366",
            &ctx.ip,
        );
        Some(WafRuleHit {
            response: Some(create_response(html, StatusCode::FORBIDDEN).unwrap()),
            matched_rule: hit_rule_keyword,
            action: "Block".to_string(),
        })
    }
}
