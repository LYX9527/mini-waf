pub mod routes;

use crate::config;
use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tokio::net::TcpListener;

/// 启动管理 API 服务
pub async fn start_admin_server(state: Arc<AppState>) {
    let app = Router::new()
        .route("/rules", get(routes::get_rules))
        .route("/rules", post(routes::add_rule))
        .with_state(state);

    let listener = TcpListener::bind(config::ADMIN_ADDR).await.unwrap();
    println!("⚙️ 管理控制台 API 启动成功，监听 http://{}", config::ADMIN_ADDR);

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("管理 API 运行异常: {}", e);
    }
}
