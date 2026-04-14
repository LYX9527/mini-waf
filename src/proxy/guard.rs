use super::handler::RequestContext;
use super::response::*;
use crate::config;
use crate::state::{AppState, AttackLog};
use chrono::Local;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Response, StatusCode};
/// Stage 0: 低级自动化脚本嗅探 (User-Agent 检查)
pub fn is_bot(ctx: &RequestContext) -> bool {
    ctx.user_agent.is_empty()
        || ctx.user_agent.contains("curl")
        || ctx.user_agent.contains("python")
        || ctx.user_agent.contains("go-http-client")
}

/// Stage 0.5: Cookie/Token 令牌验证 + 指纹绑定检测
pub fn verify_token(ctx: &RequestContext, state: &AppState) -> bool {
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
            if let Some(original_fp) = state.verified_tokens.get(token) {
                if original_fp.ip == ctx.ip && original_fp.user_agent == ctx.user_agent {
                    return true;
                } else {
                    // IP 或 UA 发生变化，失效旧令牌，强制重新质询
                    println!(
                        "⚠️ 环境变化，令牌失效！\n   Token: {}\n   原始环境 -> IP: {}, UA: {}\n   当前环境 -> IP: {}, UA: {}",
                        token, original_fp.ip, original_fp.user_agent, ctx.ip, ctx.user_agent
                    );
                    state.verified_tokens.invalidate(token);
                }
            }
            break;
        }
    }
    false
}

/// Stage 0.9: 质询死锁检测
/// 返回 Some(response) 表示用户仍在质询中，应拦截
pub fn check_deadlock(
    ctx: &RequestContext,
    is_verified: bool,
    state: &AppState,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    if is_verified {
        return None;
    }
    let (n1, n2) = state.captcha_answers.get(&ctx.ip)?;
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
pub fn check_penalty(
    ctx: &RequestContext,
    state: &AppState,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    let current_penalty = state.penalty_box.get(&ctx.ip).unwrap_or(0);
    println!("🤖 IP {} 当前惩罚分：{}", ctx.ip, current_penalty);

    if current_penalty >= config::PENALTY_BAN_SCORE {
        let html = render_error_page(
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
pub fn check_rate_limit(
    ctx: &RequestContext,
    is_verified: bool,
    state: &AppState,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    let count = state.rate_limiter.get(&ctx.ip).unwrap_or(0) + 1;
    state.rate_limiter.insert(ctx.ip.clone(), count);

    if count <= config::RATE_LIMIT_THRESHOLD || is_verified {
        return None;
    }

    // 基于请求计数奇偶性交替触发 JS 质询 / 数学题质询
    if count % 2 == 0 {
        // 路线 A: JS 无感质询
        println!("🤖 频率异常，触发 [JS 质询]: IP {}", ctx.ip);
        state.captcha_answers.insert(ctx.ip.clone(), (0, 0));
        let html = render_js_challenge_page(&ctx.ip, &ctx.target_url);
        Some(create_response(html, StatusCode::TOO_MANY_REQUESTS).unwrap())
    } else {
        // 路线 B: 数学题质询
        println!("🤖 频率异常，触发 [数学题质询]: IP {}", ctx.ip);
        let nanos = chrono::Utc::now().timestamp_subsec_nanos();
        let num1 = ((nanos / 1000) % 10) + 1;
        let num2 = ((nanos / 100000) % 10) + 1;
        state.captcha_answers.insert(ctx.ip.clone(), (num1, num2));
        let html = render_captcha_page(&ctx.ip, num1, num2, &ctx.target_url);
        Some(create_response(html, StatusCode::TOO_MANY_REQUESTS).unwrap())
    }
}

/// Stage 3: WAF 关键词规则匹配
/// 返回 None 表示未命中规则（安全请求）
pub async fn check_waf_rules(
    ctx: &RequestContext,
    state: &AppState,
) -> Option<Response<Either<Incoming, Full<Bytes>>>> {
    let rules = state.rules.read().await;
    let mut hit_rule = String::new();
    for rule in rules.iter() {
        if ctx.path_query.to_lowercase().contains(rule) {
            hit_rule = rule.clone();
            break;
        }
    }
    drop(rules);

    if hit_rule.is_empty() {
        return None;
    }

    // 惩罚
    let current_penalty = state.penalty_box.get(&ctx.ip).unwrap_or(0);
    let new_penalty = current_penalty + config::PENALTY_ATTACK_SCORE;
    state.penalty_box.insert(ctx.ip.clone(), new_penalty);

    println!(
        "❌ 拦截攻击！IP: {}, 惩罚分: {}/100, 规则: {}",
        ctx.ip, new_penalty, hit_rule
    );

    let log = AttackLog {
        time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        ip: ctx.ip_addr,
        path: ctx.path_query.clone(),
        matched_rule: hit_rule,
    };
    let _ = state.log_tx.send(log).await;

    let html = render_error_page(
        403,
        "REQUEST BLOCKED",
        "网关检测到您的请求中包含非法的参数或恶意代码特征，请求已被截断。",
        "#ff3366",
        &ctx.ip,
    );
    Some(create_response(html, StatusCode::FORBIDDEN).unwrap())
}
