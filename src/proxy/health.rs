use crate::state::AppState;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Duration};

pub async fn start_health_checker(state: Arc<AppState>) {
    crate::log_daemon!("DAEMON", "负载均衡探测雷达守护进程已启动...");
    loop {
        let routes = state.routes.read().await.clone();
        let mut new_healthy = HashSet::new();

        for route in routes {
            if route.route_type == crate::state::RouteType::Proxy {
                for target in route.upstream.split(',') {
                    let target = target.trim();
                    if target.is_empty() {
                        continue;
                    }

                    // Step 1: TCP 连接探测（基础层）
                    let tcp_ok = match timeout(Duration::from_secs(2), TcpStream::connect(target)).await {
                        Ok(Ok(_)) => true,
                        _ => {
                            crate::log_warn!("HEALTH", "节点 TCP 不可达，准备平滑摘除: {}", target);
                            false
                        }
                    };

                    if !tcp_ok {
                        continue;
                    }

                    // Step 2: HTTP HEAD 探针（应用层）
                    let health_path = route.health_check_path.as_deref().unwrap_or("/");
                    let http_ok = http_health_probe(target, health_path).await;

                    if http_ok {
                        new_healthy.insert(target.to_string());
                    } else {
                        // HTTP 层不响应，但 TCP 可达 → 仍标记为健康（可能是非 HTTP 服务）
                        // 降级处理：TCP 可达即认为存活，避免误杀非 HTTP 上游
                        crate::log_warn!(
                            "HEALTH",
                            "节点 {} TCP 可达但 HTTP 探针失败（降级保留为健康）",
                            target
                        );
                        new_healthy.insert(target.to_string());
                    }
                }
            }
        }

        {
            let mut healthy = state.healthy_upstreams.write().await;
            *healthy = new_healthy;
        }

        sleep(Duration::from_secs(10)).await; // 每隔 10 秒跑一轮雷达探测
    }
}

/// HTTP HEAD 探针：向上游发起 HEAD 请求，收到任何 HTTP 响应即为存活
async fn http_health_probe(target: &str, path: &str) -> bool {
    use hyper_util::rt::TokioIo;

    let stream = match timeout(Duration::from_secs(3), TcpStream::connect(target)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
    {
        Ok(v) => v,
        Err(_) => return false,
    };

    tokio::task::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method(hyper::Method::HEAD)
        .uri(path)
        .header(hyper::header::HOST, target)
        .header(hyper::header::USER_AGENT, "MiniWAF-HealthCheck/1.0")
        .body(http_body_util::Empty::<hyper::body::Bytes>::new());

    let req = match req {
        Ok(r) => r,
        Err(_) => return false,
    };

    match timeout(Duration::from_secs(3), sender.send_request(req)).await {
        Ok(Ok(_resp)) => true, // 收到任何 HTTP 响应（含 4xx/5xx）即表示应用层存活
        _ => false,
    }
}
