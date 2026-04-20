pub mod challenge;
pub mod guard;
pub mod handler;
pub mod health;
pub mod response;
pub mod router;
pub mod tls;

use crate::config;
use crate::state::AppState;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// 启动 WAF 代理服务
pub async fn start_proxy_server(state: Arc<AppState>) {
    let addr = SocketAddr::from(config::PROXY_ADDR);
    let listener = TcpListener::bind(addr).await.unwrap();
    crate::log_success!("HTTP_PROXY", "WAF 防御代理启动成功，监听 http://{}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let state_clone = state.clone();

        tokio::task::spawn(async move {
            let svc = service_fn(move |req| {
                handler::handle_request(req, remote_addr, state_clone.clone())
            });

            if let Err(err) = http1::Builder::new()
                .half_close(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await {
                if !err.to_string().contains("connection closed") {
                    crate::log_warn!("HTTP_PROXY", "客户端连接断开/失败: {:?}", err);
                }
            }
        });
    }
}
