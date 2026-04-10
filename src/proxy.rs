use crate::state::{AppState, AttackLog, ClientFingerprint};
use chrono::Local;
use chrono::Utc; // 确保顶部引入了 chrono
use http_body_util::BodyExt;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

async fn handle_request(
    mut req: Request<Incoming>,
    remote_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let ip_str = remote_addr.ip().to_string();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let target_url = if path_query.starts_with("/.waf") || path_query == "/favicon.ico" {
        "/"
    } else {
        path_query.as_str()
    };
    // ==========================================
    // ⭐ 关卡 0：低级自动化脚本嗅探 (User-Agent 检查)
    // ==========================================
    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if user_agent.is_empty()
        || user_agent.contains("curl")
        || user_agent.contains("python")
        || user_agent.contains("go-http-client")
    {
        println!("🛡️ 发现可疑 UA，强制触发 JS 浏览器质询: {}", user_agent);
        let html = render_js_challenge_page(&ip_str,target_url);
        return create_response(html, StatusCode::SERVICE_UNAVAILABLE);
    }
    let mut is_verified = false;
    if let Some(cookie_header) = req.headers().get(hyper::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if part.starts_with("waf_clearance=") {
                    let token = &part[14..];

                    // 去缓存里查找这个 Token 对应的原始指纹
                    if let Some(original_fp) = state.verified_tokens.get(token) {
                        // ⚔️ 核心防御：对比 IP 和 User-Agent 是否完全一致！
                        if original_fp.ip == ip_str && original_fp.user_agent == user_agent {
                            is_verified = true;
                        } else {
                            // 一旦发现不一致，说明 Cookie 被盗用或者用户环境发生了异动
                            println!(
                                "🚨 [高危告警] 拦截到 Cookie 盗用或环境突变！\n   Token: {}\n   期望环境 -> IP: {}, UA: {}\n   实际环境 -> IP: {}, UA: {}",
                                token, original_fp.ip, original_fp.user_agent, ip_str, user_agent
                            );

                            // 立刻吊销这个被污染的 Token
                            state.verified_tokens.invalidate(token);

                            // 给黑客增加 100 分惩罚，直接打入小黑屋
                            state.penalty_box.insert(ip_str.clone(), 100);
                        }
                    }
                    break;
                }
            }
        }
    }

    if path_query == "/.waf/js_verify" && req.method() == hyper::Method::POST {
        let whole_body = req.collect().await?.to_bytes();
        let body_str = String::from_utf8_lossy(&whole_body);

        let mut js_token = String::new();
        let mut redirect_url = String::from("/"); // 默认首页
        for pair in body_str.split('&') {
            let mut parts = pair.split('=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k == "fp" { js_token = v.to_string(); }
                // ⭐ 新增：解析前端传来的重定向目的地，并解码
                else if k == "redirect" { redirect_url = percent_decode(v); }
            }
        }

        // 只要 JS 能成功执行并提交了数据（非空），我们就认为它是真实浏览器
        if !js_token.is_empty() {
            println!("✅ IP {} JS 质询通过！检测到真实浏览器引擎。", ip_str);

            let clearance_token = Uuid::new_v4().to_string();
            let fingerprint = ClientFingerprint {
                ip: ip_str.clone(),
                user_agent: user_agent.clone(),
            };
            state
                .verified_tokens
                .insert(clearance_token.clone(), fingerprint);
            state.rate_limiter.invalidate(&ip_str);
            state.rate_limiter.invalidate(&ip_str);
            state.captcha_answers.invalidate(&ip_str);
            let cookie_string = format!(
                "waf_clearance={}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
                clearance_token
            );
            let response = Response::builder()
                .status(StatusCode::FOUND)
                .header(hyper::header::LOCATION, redirect_url) //
                .header(hyper::header::SET_COOKIE, cookie_string)
                .body(Either::Right(Full::new(Bytes::from(""))))
                .unwrap();
            return Ok(response);
        }
        // ⭐ 新增：加上这个 else 块，彻底堵死向下掉落的漏洞！
        else {
            println!("❌ IP {} JS 质询失败（Token 为空），拦截！", ip_str);
            let html = render_error_page(
                403,
                "CHALLENGE FAILED",
                "环境安全检测失败，拒绝访问。",
                "#ff0033",
                &ip_str,
            );
            return create_response(html, StatusCode::FORBIDDEN);
        }
    }
    // ==========================================
    // ⭐ 特殊路由：处理用户提交的验证码表单
    // ==========================================
    if path_query == "/.waf/verify" && req.method() == hyper::Method::POST {
        // 读取表单数据
        let whole_body = req.collect().await?.to_bytes();
        let body_str = String::from_utf8_lossy(&whole_body);

        // 简单解析表单 (获取 answer=xxx)
        let mut user_answer: u32 = 0;
        let mut redirect_url = String::from("/"); // 默认首页
        for pair in body_str.split('&') {
            let mut parts = pair.split('=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k == "answer" { user_answer = v.parse().unwrap_or(0); }
                // ⭐ 新增：解析重定向目的地
                else if k == "redirect" { redirect_url = percent_decode(v); }
            }
        }

        // 校验答案
        // ⭐ 修改：从元组中取出两个数相加，算出正确答案
        let expected_answer = match state.captcha_answers.get(&ip_str) {
            Some((n1, n2)) => n1 + n2,
            None => 999999, // 如果超时不存在，设置一个不可能答对的值
        };

        println!("用户提交: {}, 期望答案: {}", user_answer, expected_answer);

        if user_answer == expected_answer {
            println!("✅ IP {} 人机验证通过！颁发 Cookie 令牌。", ip_str);

            let clearance_token = Uuid::new_v4().to_string();

            // ⭐ 采集当前用户的环境特征，生成指纹并存入缓存
            let fingerprint = ClientFingerprint {
                ip: ip_str.clone(),
                user_agent: user_agent.clone(),
            };
            state
                .verified_tokens
                .insert(clearance_token.clone(), fingerprint);

            // 3. 清除限流和惩罚记录
            state.rate_limiter.invalidate(&ip_str);
            state.penalty_box.invalidate(&ip_str);
            state.captcha_answers.invalidate(&ip_str);

            // ⭐ 4. 构造包含 Set-Cookie 的 302 重定向响应
            // HttpOnly 保证脚本无法通过 JS 窃取 Cookie
            let cookie_string = format!(
                "waf_clearance={}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
                clearance_token
            );

            let response = Response::builder()
                .status(StatusCode::FOUND)
                .header(hyper::header::LOCATION, redirect_url)
                .header(hyper::header::SET_COOKIE, cookie_string) // 下发令牌！
                .body(Either::Right(Full::new(Bytes::from(""))))
                .unwrap();
            return Ok(response);
        } else {
            println!("❌ IP {} 人机验证失败。", ip_str);
            let html = render_error_page(
                403,
                "VERIFICATION FAILED",
                "人机验证失败，请退回上一页重新尝试。",
                "#ff0033",
                &ip_str,
            );
            return create_response(html, StatusCode::FORBIDDEN);
        }
    }

    // ==========================================
    // 检查白名单 (拥有免死金牌的用户直接跳过限流)
    // ==========================================
    if let Some((n1, n2)) = state.captcha_answers.get(&ip_str) {
        if !is_verified {
            if n1 == 0 && n2 == 0 {
                // 如果发现是 (0, 0)，说明它中了 JS 质询的死锁
                println!("🤖 IP {} 仍处于 [JS 质询死锁] 状态，强制拦截", ip_str);
                let html = render_js_challenge_page(&ip_str,target_url);
                return create_response(html, StatusCode::SERVICE_UNAVAILABLE);
            } else {
                // 否则就是中了数学题的死锁，原样返回老题目
                println!("🤖 IP {} 仍处于 [数学题死锁] 状态，继续显示验证码", ip_str);
                let html = render_captcha_page(&ip_str, n1, n2,target_url);
                return create_response(html, StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }
    // ==========================================
    // 关卡 1：小黑屋检查 (最优先，直接拒绝恶意 IP)
    // ==========================================
    let current_penalty = state.penalty_box.get(&ip_str).unwrap_or(0);
    println!(
        "🤖 IP {} 当前惩罚分：{} 是否通过验证{}",
        ip_str, current_penalty, is_verified
    );
    if current_penalty >= 100 {
        // 如果惩罚分达到 100，直接无情拒绝
        let html = render_error_page(
            403,
            "ACCESS DENIED",
            "您的 IP 因存在严重或频繁的恶意扫描行为，已被防御矩阵自动拉入黑名单。",
            "#ff0033", // 刺眼的血红色
            &ip_str,
        );
        return create_response(html, StatusCode::FORBIDDEN);
    }

    // ==========================================
    // 关卡 2：高频 CC 攻击限流 (429 Too Many Requests)
    // ==========================================
    // 获取当前访问次数，加 1 后写回
    let count = state.rate_limiter.get(&ip_str).unwrap_or(0) + 1;
    state.rate_limiter.insert(ip_str.clone(), count);

    // 阈值设定：10 秒内超过 20 次访问（你可以根据需要调大）
    if count > 20 && !is_verified {
        let nanos = chrono::Utc::now().timestamp_subsec_nanos();

        // ⭐ 核心优化：利用纳秒时间戳的奇偶性，实现 50% 概率的随机防御 (A/B 质询)
        // 我们除以 10 跳过个位的可能误差，然后对 2 取模
        if (nanos / 10) % 2 == 0 {
            // --------------------------------------------------
            // 路线 A (50% 概率)：触发 JS 无感质询 (Cloudflare 风格)
            // --------------------------------------------------
            println!("🤖 频率异常，触发 [JS 质询]: IP {}", ip_str);
            state.captcha_answers.insert(ip_str.clone(), (0, 0));
            let html = render_js_challenge_page(&ip_str,target_url);
            return create_response(html, StatusCode::TOO_MANY_REQUESTS); // 429
        } else {
            // --------------------------------------------------
            // 路线 B (50% 概率)：触发数学题人工质询
            // --------------------------------------------------
            println!("🤖 频率异常，触发 [数学题质询]: IP {}", ip_str);

            let num1 = ((nanos / 1000) % 10) + 1;
            let num2 = ((nanos / 100000) % 10) + 1;

            // 将题目答案存入缓存，开启质询死锁状态
            // 注意：一旦走入路线 B，顶部的 has_active_challenge 锁就会生效
            // 用户在答对之前，将永远被锁定在数学题页面，无法再随机出 JS 页面
            state.captcha_answers.insert(ip_str.clone(), (num1, num2));

            // 渲染全新高科技人机验证界面
            let html = render_captcha_page(&ip_str, num1, num2,target_url);
            return create_response(html, StatusCode::TOO_MANY_REQUESTS); // 429
        }
    }
    // 1. 获取读锁，扫描安全性
    let rules = state.rules.read().await;
    let mut is_attack = false;
    let mut hit_rule = String::new();

    for rule in rules.iter() {
        if path_query.to_lowercase().contains(rule) {
            is_attack = true;
            hit_rule = rule.clone();
            break;
        }
    }
    drop(rules);

    // 2. 拦截与记录日志
    if is_attack {
        // 🚨 触发惩罚机制：每次拦截增加 50 分惩罚值
        let new_penalty = current_penalty + 50;
        state.penalty_box.insert(ip_str.clone(), new_penalty);

        println!(
            "❌ 拦截攻击！IP: {}, 惩罚分: {}/100, 规则: {}",
            ip_str, new_penalty, hit_rule
        );
        let log = AttackLog {
            time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            ip: remote_addr,
            path: path_query.to_string(),
            matched_rule: hit_rule,
        };
        let _ = state.log_tx.send(log).await;
        let html = render_error_page(
            403,
            "REQUEST BLOCKED",
            "网关检测到您的请求中包含非法的参数或恶意代码特征，请求已被截断。",
            "#ff3366", // 霓虹粉红色
            &ip_str,
        );
        return create_response(html, StatusCode::FORBIDDEN);
    }

    let req_path = req.uri().path().to_string(); // 获取纯路径 (不含参数)
    let req_query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default(); // 获取参数

    let routes = state.routes.read().await;
    let mut matched_upstream = String::new();
    let mut matched_prefix = String::new();

    // 1. 遍历内存路由表寻找匹配项
    for (prefix, upstream) in routes.iter() {
        if req_path.starts_with(prefix) {
            // 安全性检查：确保是干净的路径节点匹配
            // 例如 prefix 是 "/oa"，那么 "/oa/login" 匹配，但 "/oabbb" 不能匹配！
            if req_path.len() == prefix.len() || req_path.as_bytes()[prefix.len()] == b'/' {
                matched_upstream = upstream.clone();
                matched_prefix = prefix.clone();
                break;
            }
        }
    }
    drop(routes);

    if matched_upstream.is_empty() {
        // 找不到匹配的路由，说明用户访问了未开放的微服务
        println!("👻 未知微服务路径被拒绝: {}", req_path);
        let html = render_error_page(
            404,
            "MICROSERVICE NOT FOUND",
            "API 网关无法在注册表中找到匹配该请求前缀的下游微服务节点。",
            "#00f0ff",
            &ip_str,
        );
        return create_response(html, StatusCode::NOT_FOUND);
    }

    // 2. ⚔️ URL 重写核心逻辑 (URL Rewrite / Strip Prefix)
    // 我们必须把网关前缀抹掉。比如浏览器访问 `/oa/api/login`，转发给后端时必须是 `/api/login`
    let mut rewritten_path = req_path[matched_prefix.len()..].to_string();

    // 如果重写后是空的，补上根路径 "/"
    if rewritten_path.is_empty() || !rewritten_path.starts_with('/') {
        rewritten_path.insert(0, '/');
    }

    // 重新拼接完整的 URI (包含重写后的路径 + 原有的参数)
    let new_uri_string = format!("{}{}", rewritten_path, req_query);

    // 强制修改当前 HTTP 请求的 URI 属性！(Rust 的黑魔法操作)
    if let Ok(new_uri) = new_uri_string.parse::<hyper::Uri>() {
        *req.uri_mut() = new_uri;
    }

    println!(
        "🔀 API 网关分发: [服务区:{}] {} -> 节点:{} (发往后端的实际URI: {})",
        matched_prefix, req_path, matched_upstream, new_uri_string
    );

    // 3. 连接到真实的下游微服务节点
    let stream = match TcpStream::connect(&matched_upstream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 无法连接到下游微服务 {}: {}", matched_upstream, e);
            let html = render_error_page(
                502,
                "DOWNSTREAM UNAVAILABLE",
                "API 网关运行正常，但被路由的下游微服务节点宕机或拒绝连接。",
                "#b142f5",
                &ip_str,
            );
            return create_response(html, StatusCode::BAD_GATEWAY);
        }
    };

    // --- 下面的转发代码保持不变 ---
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("与后端的连接异常: {:?}", err);
        }
    });

    let response = sender.send_request(req).await?;
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Either::Left(body)))
}
// 辅助函数：快速构造拦截响应，让代码更清爽
fn create_response(
    html: String,
    status: StatusCode,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let body = Either::Right(Full::new(Bytes::from(html)));
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(resp)
}
// 启动 WAF 代理服务
pub async fn start_proxy_server(state: Arc<AppState>) {
    let addr = SocketAddr::from(([0, 0, 0, 0], 48080));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("🛡️ WAF 代理启动成功，监听 http://{}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let state_clone = state.clone();

        tokio::task::spawn(async move {
            let svc = service_fn(move |req| handle_request(req, remote_addr, state_clone.clone()));

            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                eprintln!("客户端连接失败: {:?}", err);
            }
        });
    }
}
// 统一的错误页面生成器
fn render_error_page(
    status_code: u16,
    title: &str,
    message: &str,
    theme_color: &str,
    client_ip: &str,
) -> String {
    // 生成一个假的“追踪 ID”以增加企业级科技感 (基于当前纳秒时间戳的十六进制)
    let trace_id = format!("WAF-{:X}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_code} | WAF Intercepted</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #c9d1d9;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            overflow: hidden;
        }}
        .waf-card {{
            background: rgba(22, 27, 34, 0.8);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 40px 50px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 20px {theme_color}33;
            max-width: 500px;
            width: 100%;
            position: relative;
            backdrop-filter: blur(10px);
        }}
        .waf-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 4px;
            background: {theme_color};
            box-shadow: 0 0 15px {theme_color};
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
        }}
        .status-code {{
            font-size: 80px;
            font-weight: 800;
            margin: 0;
            color: {theme_color};
            text-shadow: 0 0 20px {theme_color}66;
            line-height: 1;
        }}
        .title {{ font-size: 24px; color: #fff; margin: 15px 0 10px; font-weight: 600; }}
        .message {{ font-size: 15px; color: #8b949e; margin-bottom: 35px; line-height: 1.6; }}
        .divider {{ height: 1px; background: #30363d; margin-bottom: 20px; }}
        .meta-info {{ font-size: 13px; color: #484f58; display: grid; gap: 8px; }}
        .meta-row {{ display: flex; justify-content: space-between; }}
        .meta-label {{ text-transform: uppercase; letter-spacing: 1px; }}
        .meta-value {{ color: #a5d6ff; }}
    </style>
</head>
<body>
    <div class="waf-card">
        <h1 class="status-code">{status_code}</h1>
        <div class="title">{title}</div>
        <div class="message">{message}</div>
        <div class="divider"></div>
        <div class="meta-info">
            <div class="meta-row">
                <span class="meta-label">Client IP</span>
                <span class="meta-value">{client_ip}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Ray ID</span>
                <span class="meta-value">{trace_id}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Engine</span>
                <span class="meta-value">Rust Mini-WAF v1.0</span>
            </div>
        </div>
    </div>
</body>
</html>"#,
        status_code = status_code,
        title = title,
        message = message,
        theme_color = theme_color,
        client_ip = client_ip,
        trace_id = trace_id
    )
}
// 专属的“赛博朋克人机验证”页面生成器
fn render_captcha_page(client_ip: &str, num1: u32, num2: u32, redirect_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF矩阵 | 质询</title>
    <style>
        body {{ background-color: #0b0f19; color: #c9d1d9; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .waf-card {{ background: rgba(22, 27, 34, 0.8); border: 1px solid #30363d; border-radius: 12px; padding: 40px; box-shadow: 0 0 30px rgba(0, 240, 255, 0.2); max-width: 450px; width: 90%; text-align: center; backdrop-filter: blur(10px); position: relative; }}

        /* ⭐ 新增：CSS手搓的几何线条发光盾牌 */
        .shield-icon {{ width: 60px; height: 70px; margin: 0 auto 15px; position: relative; border: 3px solid #00f0ff; border-top: none; border-radius: 0 0 50% 50% / 0 0 20px 20px; box-shadow: 0 0 15px rgba(0, 240, 255, 0.5), inset 0 0 10px rgba(0, 240, 255, 0.2); }}
        .shield-icon::before {{ content: ''; position: absolute; top: -10px; left: -3px; width: 66px; height: 10px; background: #0b0f19; border-left: 3px solid #00f0ff; border-right: 3px solid #00f0ff; border-radius: 5px 5px 0 0; }}
        .shield-icon::after {{ content: ''; position: absolute; top: 15px; left: 15px; width: 30px; height: 35px; border-left: 3px solid #00f0ff; border-bottom: 3px solid #00f0ff; border-radius: 0 0 5px 25px / 0 0 5px 15px; transform: rotate(-45deg); opacity: 0.7; }}

        .title {{ color: #00f0ff; font-size: 20px; font-weight: bold; margin-bottom: 12px; text-shadow: 0 0 10px rgba(0, 240, 255, 0.5); text-transform: uppercase; letter-spacing: 2px; }}
        .desc {{ color: #8b949e; font-size: 14px; line-height: 1.6; margin-bottom: 30px; }}
        .captcha-box {{ background: #0d1117; border: 1px solid #30363d; padding: 25px 20px; border-radius: 8px; margin-bottom: 25px; box-shadow: inset 0 0 15px rgba(0,0,0,0.3); }}

        /* ⭐ 优化题目：风格统一 */
        .math-problem {{ font-size: 26px; color: #fff; letter-spacing: 3px; margin-bottom: 20px; font-weight: bold; }}
        .math-problem span {{ color: #00f0ff; text-shadow: 0 0 5px rgba(0, 240, 255, 0.3); }}

        /* ⭐ 优化输入框：去掉原生输入框箭头，设置自定义深色发光风格 */
        input[type="number"] {{ background: #010409; border: 1px solid #30363d; color: #00f0ff; padding: 12px 15px; font-size: 20px; width: 120px; text-align: center; border-radius: 4px; outline: none; transition: all 0.3s ease; font-family: monospace; -moz-appearance: textfield; }}
        input[type="number"]::-webkit-outer-spin-button, input[type="number"]::-webkit-inner-spin-button {{ -webkit-appearance: none; margin: 0; }}
        input[type="number"]:focus {{ border-color: #00f0ff; box-shadow: 0 0 15px rgba(0, 240, 255, 0.4); }}

        button {{ background: transparent; border: 1px solid #00f0ff; color: #00f0ff; padding: 12px 35px; font-size: 15px; cursor: pointer; border-radius: 4px; transition: all 0.3s ease; text-transform: uppercase; font-family: monospace; font-weight: bold; margin-top: 10px; letter-spacing: 1px; }}
        button:hover {{ background: #00f0ff; color: #000; box-shadow: 0 0 25px rgba(0, 240, 255, 0.7); text-shadow: none; }}
        .ip-info {{ margin-top: 35px; font-size: 11px; color: #484f58; letter-spacing: 1px; }}
    </style>
</head>
<body>
    <div class="waf-card">
        <div class="shield-icon"></div>
        <div class="title">Security Challenge</div>
        <div class="desc">系统检测到您的网络请求频率异常。<br>请证明您是人类，以继续访问该网站。</div>

        <form action="/.waf/verify" method="POST">
            <input type="hidden" name="redirect" value="{}">

            <div class="captcha-box">
                <div class="math-problem">{} + {} = ?</div>
                <input type="number" name="answer" required autocomplete="off" placeholder="答案">
            </div>
            <button type="submit">Verify Now / 提交验证</button>
        </form>

        <div class="ip-info">Client IP: {} | Rust WAF 矩阵安全防御系统 v1.0</div>
    </div>
</body>
</html>"#,
        redirect_url, num1, num2, client_ip
    )
}

// 专属的 JS 无感质询页面 (Cloudflare 5秒盾风格)
fn render_js_challenge_page(client_ip: &str, redirect_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checking your browser...</title>
    <style>
        body {{ background-color: #0b0f19; color: #c9d1d9; font-family: 'SFMono-Regular', Consolas, monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; flex-direction: column; }}
        .spinner {{ width: 50px; height: 50px; border: 3px solid rgba(0, 240, 255, 0.1); border-radius: 50%; border-top-color: #00f0ff; animation: spin 1s ease-in-out infinite; margin-bottom: 30px; box-shadow: 0 0 15px rgba(0,240,255,0.2); }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        h2 {{ color: #00f0ff; font-weight: normal; letter-spacing: 1px; font-size: 20px; }}
        p {{ color: #8b949e; font-size: 14px; max-width: 400px; text-align: center; line-height: 1.6; }}
    </style>
</head>
<body>
    <div class="spinner"></div>
    <h2>WAF 防御矩阵正在验证您的环境</h2>
    <p>请稍候，这通常需要几秒钟。我们将验证您使用的是安全的浏览器而非自动化脚本。</p>
    <p style="font-size: 12px; margin-top: 20px; opacity: 0.5;">Client IP: {}</p>

    <form id="challenge-form" action="/.waf/js_verify" method="POST" style="display:none;">
        <input type="hidden" name="fp" id="fp_input" value="">
    </form>
    <form id="challenge-form" action="/.waf/js_verify" method="POST" style="display:none;">
        <input type="hidden" name="fp" id="fp_input" value="">
        <input type="hidden" name="redirect" value="{}">
    </form>
    <script>
        // 【核心防御逻辑】：只有真正的浏览器才能执行这段 JS
        setTimeout(function() {{
            // 1. 采集极其基础的浏览器指纹 (屏幕宽高 + 颜色深度 + 时区)
            // curl 脚本根本没有 window.screen 和 Date，所以无法伪造这个值
            var screenData = window.screen ? (window.screen.width + "x" + window.screen.height + "-" + window.screen.colorDepth) : "headless";
            var timezone = new Date().getTimezoneOffset();

            // 2. 将数据组合成一个简单的指纹 Token (这里用 btoa 做 base64 编码演示)
            var rawFingerprint = screenData + "|" + timezone;
            var jsToken = btoa(rawFingerprint);

            // 3. 填入隐藏表单并自动提交
            document.getElementById('fp_input').value = jsToken;
            document.getElementById('challenge-form').submit();
        }}, 2500); // 故意延迟 2.5 秒，消耗黑客扫描器的时间成本 (Tarpit 机制)
    </script>
</body>
</html>"#,
        client_ip,redirect_url
    )
}
// 迷你 URL 解码器 (处理表单提交的 %2F 等字符)
fn percent_decode(input: &str) -> String {
    let mut res = String::new();
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                res.push(byte as char);
            } else {
                res.push('%');
                res.push_str(&hex);
            }
        } else if c == '+' {
            res.push(' ');
        } else {
            res.push(c);
        }
    }
    res
}
