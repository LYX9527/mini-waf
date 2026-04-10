use super::handler::RequestContext;
use super::response::*;
use crate::state::AppState;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Stage 4+5: 路由匹配 + URL 重写 + 反向代理
pub async fn route_and_proxy(
    mut req: Request<hyper::body::Incoming>,
    ctx: &RequestContext,
    state: &AppState,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let routes = state.routes.read().await;
    let mut matched_upstream = String::new();
    let mut matched_prefix = String::new();

    for (prefix, upstream) in routes.iter() {
        if ctx.path.starts_with(prefix) {
            // 确保是干净的路径节点匹配
            if ctx.path.len() == prefix.len() || ctx.path.as_bytes()[prefix.len()] == b'/' {
                matched_upstream = upstream.clone();
                matched_prefix = prefix.clone();
                break;
            }
        }
    }
    drop(routes);

    if matched_upstream.is_empty() {
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

    // URL 重写：剥离网关前缀
    let mut rewritten_path = ctx.path[matched_prefix.len()..].to_string();
    if rewritten_path.is_empty() || !rewritten_path.starts_with('/') {
        rewritten_path.insert(0, '/');
    }
    let new_uri_string = format!("{}{}", rewritten_path, ctx.query);

    if let Ok(new_uri) = new_uri_string.parse::<hyper::Uri>() {
        *req.uri_mut() = new_uri;
    }

    println!(
        "🔀 API 网关分发: [服务区:{}] {} -> 节点:{} (发往后端的实际URI: {})",
        matched_prefix, ctx.path, matched_upstream, new_uri_string
    );

    // 连接后端微服务
    let stream = match TcpStream::connect(&matched_upstream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 无法连接到下游微服务 {}: {}", matched_upstream, e);
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
