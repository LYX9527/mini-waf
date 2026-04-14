use super::response::*;
use super::{challenge, guard, router};
use crate::state::{AccessLog, AppState};
use http_body_util::{Either, Full};
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// 请求上下文 —— 从原始请求中提取的常用字段，避免重复解析
pub struct RequestContext {
    pub ip: String,
    pub ip_addr: SocketAddr,
    pub user_agent: String,
    pub path_query: String,
    pub path: String,
    pub query: String,
    pub target_url: String,
    pub method: Method,
    pub raw_headers: HeaderMap<HeaderValue>,
}

impl RequestContext {
    pub fn new(req: &Request<Incoming>, remote_addr: SocketAddr) -> Self {
        let ip_str = remote_addr.ip().to_string();
        let path_query = req
            .uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let path = req.uri().path().to_string();
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default();
        let user_agent = req
            .headers()
            .get(hyper::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let target_url = if path_query.starts_with("/.waf") || path_query == "/favicon.ico" {
            "/"
        } else {
            &path_query
        }
        .to_string();

        Self {
            ip: ip_str,
            ip_addr: remote_addr,
            user_agent,
            path_query,
            path,
            query,
            target_url,
            method: req.method().clone(),
            raw_headers: req.headers().clone(),
        }
    }

    pub fn is_waf_endpoint(&self) -> bool {
        self.path_query == "/.waf/js_verify" || self.path_query == "/.waf/verify"
    }
}

/// 判断路径是否为常见的静态资源文件（前端碎片文件）
fn is_static_asset_path(path: &str) -> bool {
    let ext = match path.rfind('.') {
        Some(pos) => &path[pos + 1..],
        None => return false,
    };
    let ext = ext.split(|c| c == '?' || c == '#').next().unwrap_or(ext);
    matches!(
        ext,
        "js" | "mjs" | "css" | "map"
            | "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" | "webp" | "avif"
            | "woff" | "woff2" | "ttf" | "otf" | "eot"
            | "mp4" | "webm" | "mp3" | "ogg"
            | "wasm" | "json" | "xml" | "txt"
    )
}

/// 发送访问日志
fn send_access_log(state: &AppState, ctx: &RequestContext, status_code: u16, is_blocked: bool, matched_rule: Option<String>) {
    let referer = ctx
        .raw_headers
        .get(hyper::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let log = AccessLog {
        ip: ctx.ip.clone(),
        path: ctx.path_query.clone(),
        method: ctx.method.to_string(),
        status_code,
        is_blocked,
        matched_rule,
        user_agent: ctx.user_agent.clone(),
        referer,
    };
    let _ = state.access_log_tx.try_send(log);
}

/// 请求处理管线 —— 按安全关卡顺序依次检查
pub async fn handle_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = RequestContext::new(&req, remote_addr);

    // 原子计数器：总请求数 +1
    let total = state.counters.total_requests_today.fetch_add(1, Ordering::Relaxed) + 1;

    // QPS 滑动窗口：记录请求时间戳和累计计数
    {
        let now = std::time::Instant::now();
        let mut window = state.counters.qps_window.write().await;
        window.push_back((now, total));
        // 清理 10 秒前的数据
        let cutoff = now - std::time::Duration::from_secs(10);
        while let Some(&(t, _)) = window.front() {
            if t < cutoff {
                window.pop_front();
            } else {
                break;
            }
        }
    }

    // Stage -1: IP 黑白名单检查
    {
        let whitelist = state.ip_whitelist.read().await;
        if whitelist.contains(&ctx.ip) {
            drop(whitelist);
            // 白名单直接跳过所有安全检查
            send_access_log(&state, &ctx, 200, false, None);
            return router::route_and_proxy(req, &ctx, &state).await;
        }
        drop(whitelist);

        let blacklist = state.ip_blacklist.read().await;
        if blacklist.contains(&ctx.ip) {
            drop(blacklist);
            state.counters.blocked_requests_today.fetch_add(1, Ordering::Relaxed);
            let custom_page = state.custom_block_page.read().await.clone();
            let html = render_error_page(
                Some(&custom_page),
                403,
                "ACCESS DENIED",
                "您的 IP 已被管理员加入黑名单。",
                "#ff0033",
                &ctx.ip,
            );
            send_access_log(&state, &ctx, 403, true, Some("ip_blacklist".to_string()));
            return create_response(html, StatusCode::FORBIDDEN);
        }
        drop(blacklist);

        // Stage -0.5: Geo-Blocking
        if let Some(ref db) = state.geo_db {
            if let Ok(country) = db.lookup::<maxminddb::geoip2::Country>(ctx.ip_addr.ip()) {
                if let Some(iso_code) = country.country.and_then(|c| c.iso_code) {
                    let blocked_countries = state.geo_blocked_countries.read().await;
                    if blocked_countries.contains(iso_code) {
                        drop(blocked_countries);
                        state.counters.blocked_requests_today.fetch_add(1, Ordering::Relaxed);
                        let custom_page = state.custom_block_page.read().await.clone();
                        let html = render_error_page(
                            Some(&custom_page),
                            403,
                            "GEO BLOCKED",
                            &format!("根据访问访问控制策略，您所在的地理区域（{}）已被拒绝访问。", iso_code),
                            "#ff4d4f",
                            &ctx.ip,
                        );
                        send_access_log(&state, &ctx, 403, true, Some(format!("geo_blocked_{}", iso_code)));
                        return create_response(html, StatusCode::FORBIDDEN);
                    }
                }
            }
        }
    }

    // Stage 0: UA 嗅探
    if guard::is_bot(&ctx) {
        println!("🛡️ 发现可疑 UA，强制触发 JS 浏览器质询: {}", ctx.user_agent);
        state.counters.blocked_requests_today.fetch_add(1, Ordering::Relaxed);
        let html = render_js_challenge_page(&ctx.ip, &ctx.target_url);
        send_access_log(&state, &ctx, 503, true, Some("bot_detection".to_string()));
        return create_response(html, StatusCode::SERVICE_UNAVAILABLE);
    }

    // Stage 0.5: 令牌验证
    let is_verified = guard::verify_token(&ctx, &state);

    // Stage 0.75: WAF 内部端点 (质询提交)
    if ctx.is_waf_endpoint() {
        let resp = challenge::handle_challenge_endpoint(&ctx, req, &state).await;
        send_access_log(&state, &ctx, resp.status().as_u16(), false, None);
        return Ok(resp);
    }

    // Stage 0.9: 质询死锁检测
    if let Some(resp) = guard::check_deadlock(&ctx, is_verified, &state) {
        state.counters.blocked_requests_today.fetch_add(1, Ordering::Relaxed);
        send_access_log(&state, &ctx, resp.status().as_u16(), true, Some("challenge_deadlock".to_string()));
        return Ok(resp);
    }

    let is_static_asset = is_static_asset_path(&ctx.path);

    // 已验证用户请求静态资源时，跳过惩罚、限流、WAF 规则检查
    if !is_verified || !is_static_asset {
        // Stage 1: 惩罚盒子
        if let Some(resp) = guard::check_penalty(&ctx, &state).await {
            state.counters.blocked_requests_today.fetch_add(1, Ordering::Relaxed);
            send_access_log(&state, &ctx, 403, true, Some("penalty_ban".to_string()));
            return Ok(resp);
        }

        // Stage 2: 限流
        if let Some(resp) = guard::check_rate_limit(&ctx, is_verified, &state) {
            state.counters.blocked_requests_today.fetch_add(1, Ordering::Relaxed);
            send_access_log(&state, &ctx, 429, true, Some("rate_limit".to_string()));
            return Ok(resp);
        }

        // Stage 3: WAF 规则匹配
        if let Some(resp) = guard::check_waf_rules(&ctx, &state).await {
            state.counters.blocked_requests_today.fetch_add(1, Ordering::Relaxed);
            send_access_log(&state, &ctx, 403, true, None); // matched_rule 在 guard 内部已记录
            return Ok(resp);
        }
    }

    // Stage 4+5: 路由匹配 + 反向代理/静态文件
    let result = router::route_and_proxy(req, &ctx, &state).await;
    match &result {
        Ok(resp) => {
            send_access_log(&state, &ctx, resp.status().as_u16(), false, None);
        }
        Err(_) => {
            send_access_log(&state, &ctx, 502, false, None);
        }
    }
    result
}
