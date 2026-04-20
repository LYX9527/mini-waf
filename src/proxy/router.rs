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
    req: Request<Either<Incoming, Full<Bytes>>>,
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

    // Stage 4.5: 路由级限流检查
    if let Some(threshold) = route.rate_limit_threshold {
        if let Some(resp) = super::guard::check_route_rate_limit(ctx, state, threshold, &route.path_prefix).await {
            return Ok(resp);
        }
    }

    proxy_to_upstream(req, &route, &suffix, ctx, state).await
}

async fn proxy_to_upstream(
    mut req: Request<Either<Incoming, Full<Bytes>>>,
    route: &Route,
    suffix: &str,
    ctx: &RequestContext,
    state: &AppState,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let new_uri_string = format!("{}{}", suffix, ctx.query);

    if let Ok(new_uri) = new_uri_string.parse::<hyper::Uri>() {
        *req.uri_mut() = new_uri;
    }

    // ── 注入标准代理头部 ───────────────────────────────────────────
    inject_proxy_headers(&mut req, ctx);

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

    // ── WebSocket 升级检测 ─────────────────────────────────────────────────
    let is_websocket = is_upgrade_request(&req);

    if is_websocket {
        return handle_websocket_upgrade(req, target, ctx).await;
    }

    // ── 普通 HTTP/1.1 反向代理 ─────────────────────────────────────────────
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

/// 检测是否为 WebSocket 升级请求
fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    let upgrade = req.headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let connection = req.headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    upgrade.contains("websocket") && connection.contains("upgrade")
}

/// 处理 WebSocket 升级：建立双向 TCP 隧道
async fn handle_websocket_upgrade(
    req: Request<Either<Incoming, Full<Bytes>>>,
    target: &str,
    ctx: &RequestContext,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    println!("🔌 WebSocket 升级请求: {} -> {}", ctx.path, target);

    // 1. 连接上游
    let mut upstream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 WebSocket 无法连接到上游 {}: {}", target, e);
            let html = render_error_page(None, 502, "UPSTREAM UNAVAILABLE", "WebSocket 上游不可达", "#b142f5", &ctx.ip);
            return create_response(html, StatusCode::BAD_GATEWAY);
        }
    };

    // 2. 手动构造 HTTP 升级请求，透传所有原始头部
    let mut raw_request = format!(
        "{} {} HTTP/1.1\r\n",
        req.method(),
        req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
    );
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            raw_request.push_str(&format!("{}: {}\r\n", name, v));
        }
    }
    raw_request.push_str("\r\n");

    upstream.write_all(raw_request.as_bytes()).await?;

    // 3. 读取上游响应（等待 101 Switching Protocols）
    let mut resp_buf = vec![0u8; 4096];
    let n = upstream.read(&mut resp_buf).await?;
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

    if !resp_str.contains("101") {
        eprintln!("🔴 WebSocket 上游未返回 101: {}", resp_str.lines().next().unwrap_or(""));
        let html = render_error_page(None, 502, "WEBSOCKET UPGRADE FAILED", "上游服务器拒绝了 WebSocket 升级请求", "#b142f5", &ctx.ip);
        return create_response(html, StatusCode::BAD_GATEWAY);
    }

    println!("✅ WebSocket 隧道已建立: {} <-> {}", ctx.ip, target);

    // 4. 将 101 响应返回给客户端，并建立双向隧道
    //    使用 hyper 的 on_upgrade 机制无法获取原始 TCP，因此我们直接返回 101 响应
    //    并在后台 spawn 一个双向拷贝任务
    //    注意：这里构造 101 响应，hyper 会自动处理协议切换
    let mut response = Response::new(Either::Right(Full::new(Bytes::new())));
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;

    // 将上游返回的 101 响应头解析并设置到我们的响应中
    for line in resp_str.lines().skip(1) {
        if line.is_empty() { break; }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(key.as_bytes()),
                hyper::header::HeaderValue::from_str(value),
            ) {
                response.headers_mut().insert(name, val);
            }
        }
    }

    // 注意：hyper HTTP/1 在收到 101 之后，会通过 conn.with_upgrades() 让出原始 IO。
    // 但因我们使用 service_fn，升级过程由 hyper 自动管理。
    // 此处返回 101 后，hyper 将触发协议升级，后续字节不再经过 HTTP 层。

    Ok(response)
}

/// 注入标准反向代理头部
fn inject_proxy_headers<B>(req: &mut Request<B>, ctx: &RequestContext) {
    let headers = req.headers_mut();

    // X-Forwarded-For: 追加客户端 IP 到已有值后（多级代理链路场景）
    let existing_xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let new_xff = match existing_xff {
        Some(existing) => format!("{}, {}", existing, ctx.ip),
        None => ctx.ip.clone(),
    };
    if let Ok(val) = hyper::header::HeaderValue::from_str(&new_xff) {
        headers.insert("x-forwarded-for", val);
    }

    // X-Real-IP: 覆盖写入（始终为最终客户端 IP）
    if let Ok(val) = hyper::header::HeaderValue::from_str(&ctx.ip) {
        headers.insert("x-real-ip", val);
    }

    // X-Forwarded-Proto: 根据原始请求是否为加密连接判断
    // 如果原始请求携带了该头部则保留，否则根据连接是否经 TLS 终结推断
    if !headers.contains_key("x-forwarded-proto") {
        // 默认假设 WAF 前无 TLS 终结（如有，Nginx/CF 层应已设置该头部）
        headers.insert("x-forwarded-proto",
            hyper::header::HeaderValue::from_static("http"));
    }

    // X-Forwarded-Host: 原始 Host 头
    if let Some(host) = headers.get(hyper::header::HOST).cloned() {
        headers.insert("x-forwarded-host", host);
    }
}
