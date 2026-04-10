use super::handler::RequestContext;
use super::response::*;
use super::static_file;
use crate::state::{AppState, Route, RouteType};
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Stage 4+5: 路由匹配 + 按类型分发（反向代理 或 静态文件）
pub async fn route_and_proxy(
    req: Request<hyper::body::Incoming>,
    ctx: &RequestContext,
    state: &AppState,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    // 最长前缀匹配
    let routes = state.routes.read().await;
    let matched = routes
        .iter()
        .find(|r| {
            ctx.path.starts_with(&r.path_prefix)
                && (ctx.path.len() == r.path_prefix.len()
                    || ctx.path.as_bytes()[r.path_prefix.len()] == b'/')
        })
        .cloned();
    drop(routes);

    let route = match matched {
        Some(r) => r,
        None => {
            println!("👻 未知微服务路径被拒绝: {}", ctx.path);
            let html = render_error_page(
                404,
                "MICROSERVICE NOT FOUND",
                "API 网关无法在注册表中找到匹配该请求前缀的下游微服务节点。",
                "#00f0ff",
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

    match route.route_type {
        RouteType::Proxy => proxy_to_upstream(req, &route, &suffix, ctx).await,
        RouteType::Static => {
            println!(
                "📄 静态文件服务: [前缀:{}] {} -> 目录:{} (SPA: {})",
                route.path_prefix, ctx.path, route.upstream, route.is_spa
            );
            static_file::serve_static(&route.upstream, &suffix, route.is_spa).await
        }
    }
}

/// 反向代理转发（原有逻辑）
async fn proxy_to_upstream(
    mut req: Request<hyper::body::Incoming>,
    route: &Route,
    suffix: &str,
    ctx: &RequestContext,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let new_uri_string = format!("{}{}", suffix, ctx.query);

    if let Ok(new_uri) = new_uri_string.parse::<hyper::Uri>() {
        *req.uri_mut() = new_uri;
    }

    println!(
        "🔀 API 网关分发: [服务区:{}] {} -> 节点:{} (发往后端的实际URI: {})",
        route.path_prefix, ctx.path, route.upstream, new_uri_string
    );

    let stream = match TcpStream::connect(&route.upstream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 无法连接到下游微服务 {}: {}", route.upstream, e);
            let html = render_error_page(
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
