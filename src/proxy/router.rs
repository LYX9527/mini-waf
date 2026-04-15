use super::handler::RequestContext;
use super::response::*;
use crate::state::{AppState, Route};
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// 匹配 Host 头部: 支持精确匹配和通配符 *.example.com
fn host_matches(pattern: &str, host: &str) -> bool {
    // 去掉端口号
    let host = host.split(':').next().unwrap_or(host);
    let pattern = pattern.split(':').next().unwrap_or(pattern);

    if pattern.starts_with("*.") {
        // 通配符匹配：*.example.com 匹配 a.example.com、b.example.com
        let suffix = &pattern[1..]; // .example.com
        host.ends_with(suffix) && host.len() > suffix.len()
    } else {
        // 精确匹配（忽略大小写）
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Stage 4+5: 路由匹配 + 反向代理分发
pub async fn route_and_proxy(
    req: Request<Incoming>,
    ctx: &RequestContext,
    state: &AppState,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    // 从请求头获取 Host（去掉端口号，转小写）
    let req_host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // 路由匹配：Host + 最长路径前缀
    // 优先级：有 host_pattern 的路由 > 无 host_pattern（通配）的路由
    let routes = state.routes.read().await;
    let matched = routes
        .iter()
        .find(|r| {
            // 先检查路径前缀
            let path_ok = ctx.path.starts_with(&r.path_prefix)
                && (r.path_prefix == "/"
                    || ctx.path.len() == r.path_prefix.len()
                    || ctx.path.as_bytes()[r.path_prefix.len()] == b'/');
            if !path_ok {
                return false;
            }
            // 再检查域名
            match &r.host_pattern {
                Some(pattern) => host_matches(pattern, &req_host),
                None => true, // 无 host 限制，匹配所有
            }
        })
        .cloned();
    drop(routes);

    let route = match matched {
        Some(r) => r,
        None => {
            println!("👻 未知微服务路径被拒绝: {}", ctx.path);
            let html = render_error_page(
                None,
                404,
                "ROUTE NOT FOUND",
                "网关尚未配置该路径的路由规则，或对应的微服务未开启。",
                "#13c2c2",
                &ctx.ip,
            );
            return create_response(html, StatusCode::NOT_FOUND);
        }
    };

    // 计算路径后缀（剥离路由前缀）
    let mut suffix = ctx.path[route.path_prefix.len()..].to_string();
    if suffix.is_empty() || !suffix.starts_with('/') {
        suffix.insert(0, '/');
    }

    proxy_to_upstream(req, &route, &suffix, ctx, state).await
}

async fn proxy_to_upstream(
    mut req: Request<Incoming>,
    route: &Route,
    suffix: &str,
    ctx: &RequestContext,
    state: &AppState,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let new_uri_string = format!("{}{}", suffix, ctx.query);

    if let Ok(new_uri) = new_uri_string.parse::<hyper::Uri>() {
        *req.uri_mut() = new_uri;
    }

    let mut candidates = Vec::new();
    let healthy = state.healthy_upstreams.read().await;
    let upstreams: Vec<&str> = route.upstream.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    for u in &upstreams {
        if healthy.contains(*u) {
            candidates.push(*u);
        }
    }
    drop(healthy);

    // 如果所有节点均未探测成功，降级尝试轮询全量节点，防止误杀
    if candidates.is_empty() && !upstreams.is_empty() {
        candidates = upstreams;
    }

    let target = if candidates.is_empty() {
        let html = render_error_page(None, 502, "BAD GATEWAY", "无可用下游服务节点配置", "#b142f5", &ctx.ip);
        return Ok(create_response(html, StatusCode::BAD_GATEWAY)?);
    } else {
        let count = route.rr_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        candidates[count % candidates.len()]
    };

    println!(
        "🔀 API 网关分发: [服务区:{}] {} -> 节点:{} (发往后端的实际URI: {})",
        route.path_prefix, ctx.path, target, new_uri_string
    );

    let stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 无法连接到下游微服务 {}: {}", target, e);
            let html = render_error_page(
                None,
                502,
                "DOWNSTREAM UNAVAILABLE",
                "API 网关运行正常，但被路由的下游微服务节点宕机或拒绝连接。",
                "#b142f5",
                &ctx.ip,
            );
            return create_response(html, StatusCode::BAD_GATEWAY);
        }
    };

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
