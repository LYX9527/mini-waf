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

                    match timeout(Duration::from_secs(2), TcpStream::connect(target)).await {
                        Ok(Ok(_)) => {
                            new_healthy.insert(target.to_string());
                        }
                        _ => {
                            crate::log_warn!("HEALTH", "节点状态异常，准备平滑摘除: {}", target);
                        }
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
