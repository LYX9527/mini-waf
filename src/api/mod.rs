pub mod ip_lists;
pub mod logs;
pub mod routes;
pub mod settings;
pub mod stats;

use crate::config;
use crate::state::AppState;
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

/// 启动管理 API 服务
pub async fn start_admin_server(state: Arc<AppState>) {
    let api_router = Router::new()
        // WAF 规则
        .route("/rules", get(routes::get_rules))
        .route("/rules", post(routes::add_rule))
        // 路由管理
        .route("/routes", get(routes::get_routes))
        .route("/routes", post(routes::add_route))
        .route("/routes", delete(routes::delete_route))
        .route("/routes/health-check", post(routes::health_check_route))
        // 统计面板
        .route("/stats/realtime", get(stats::get_realtime_stats))
        .route("/stats/today", get(stats::get_today_stats))
        .route("/stats/top-ips", get(stats::get_top_ips))
        .route("/stats/top-rules", get(stats::get_top_rules))
        // 日志查询
        .route("/logs/attacks", get(logs::get_attack_logs))
        .route("/logs/access", get(logs::get_access_logs))
        // 黑白名单
        .route("/ip-lists/blacklist", get(ip_lists::get_blacklist))
        .route("/ip-lists/blacklist", post(ip_lists::add_to_blacklist))
        .route(
            "/ip-lists/blacklist/{ip}",
            delete(ip_lists::remove_from_blacklist),
        )
        .route("/ip-lists/whitelist", get(ip_lists::get_whitelist))
        .route("/ip-lists/whitelist", post(ip_lists::add_to_whitelist))
        .route(
            "/ip-lists/whitelist/{ip}",
            delete(ip_lists::remove_from_whitelist),
        )
        // 系统设置
        .route("/settings", get(settings::get_settings))
        .route("/settings", put(settings::update_settings));

    // 前端静态文件目录
    let frontend_dir = "admin_frontend/dist";
    let fallback = ServeFile::new(format!("{}/index.html", frontend_dir));

    let app = Router::new()
        .nest("/api/v1", api_router)
        .fallback_service(
            ServeDir::new(frontend_dir).not_found_service(fallback),
        )
        .with_state(state);

    let listener = TcpListener::bind(config::ADMIN_ADDR).await.unwrap();
    println!(
        "⚙️ 管理控制台启动成功，监听 http://{}",
        config::ADMIN_ADDR
    );
    println!("   API 端点: http://{}/api/v1/", config::ADMIN_ADDR);
    println!("   管理面板: http://{}/", config::ADMIN_ADDR);

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("管理 API 运行异常: {}", e);
    }
}
