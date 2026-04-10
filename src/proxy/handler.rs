use super::{challenge, guard, router};
use super::response::*;
use crate::state::AppState;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{Either, Full};
use hyper::body::Bytes;
use std::net::SocketAddr;
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

        // target_url: 用于质询页面的重定向目标
        // 注意：仅当请求的是 WAF 内部页面时才回退到 "/"
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

/// 请求处理管线 —— 按安全关卡顺序依次检查
pub async fn handle_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = RequestContext::new(&req, remote_addr);

    // Stage 0: UA 嗅探
    if guard::is_bot(&ctx) {
        println!("🛡️ 发现可疑 UA，强制触发 JS 浏览器质询: {}", ctx.user_agent);
        let html = render_js_challenge_page(&ctx.ip, &ctx.target_url);
        return create_response(html, StatusCode::SERVICE_UNAVAILABLE);
    }

    // Stage 0.5: 令牌验证
    let is_verified = guard::verify_token(&ctx, &state);

    // Stage 0.75: WAF 内部端点 (质询提交)
    if ctx.is_waf_endpoint() {
        return Ok(challenge::handle_challenge_endpoint(&ctx, req, &state).await);
    }

    // Stage 0.9: 质询死锁检测
    if let Some(resp) = guard::check_deadlock(&ctx, is_verified, &state) {
        return Ok(resp);
    }

    // Stage 1: 惩罚盒子
    if let Some(resp) = guard::check_penalty(&ctx, &state) {
        return Ok(resp);
    }

    // Stage 2: 限流
    if let Some(resp) = guard::check_rate_limit(&ctx, is_verified, &state) {
        return Ok(resp);
    }

    // Stage 3: WAF 规则匹配
    if let Some(resp) = guard::check_waf_rules(&ctx, &state).await {
        return Ok(resp);
    }

    // Stage 4+5: 路由匹配 + 反向代理
    router::route_and_proxy(req, &ctx, &state).await
}
