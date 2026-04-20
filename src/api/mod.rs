pub mod auth;
pub mod ip_lists;
pub mod logs;
pub mod nginx;
pub mod routes;
pub mod settings;
pub mod ssl;
pub mod stats;

use crate::config;
use crate::state::AppState;
use axum::{
    routing::{delete, get, post, put},
    Router, middleware,
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
        .route("/rules", put(routes::edit_rule))
        .route("/rules", delete(routes::delete_rule))
        .route("/rules/toggle", post(routes::toggle_rule))
        .route("/rules/export", get(routes::export_rules))
        .route("/rules/import", post(routes::import_rules))
        .route("/rules/defaults", get(routes::get_default_rules))
        .route("/rules/load-defaults", post(routes::load_default_rules))
        // 路由管理
        .route("/routes", get(routes::get_routes))
        .route("/routes", post(routes::add_route))
        .route("/routes/edit", put(routes::edit_route))
        .route("/routes", delete(routes::real_delete_route))
        .route("/routes/disable", post(routes::disable_route))
        .route("/routes/enable", post(routes::enable_route))
        .route("/routes/health-check", post(routes::health_check_route))
        // 统计面板
        .route("/stats/realtime", get(stats::get_realtime_stats))
        .route("/stats/overview", get(stats::get_overview_stats))
        .route("/stats/today", get(stats::get_today_stats))
        .route("/stats/top-ips", get(stats::get_top_ips))
        .route("/stats/top-rules", get(stats::get_top_rules))
        .route("/stats/status-distribution", get(stats::get_status_distribution))
        .route("/stats/top-referers", get(stats::get_top_referers))
        .route("/stats/ip-geo", get(stats::get_ip_geo))
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
        .route("/settings", put(settings::update_settings))
        // Nginx 配置管理
        .route("/nginx/configs", get(nginx::list_nginx_configs))
        .route("/nginx/configs", post(nginx::add_nginx_config))
        .route("/nginx/configs", put(nginx::edit_nginx_config))
        .route("/nginx/configs", delete(nginx::delete_nginx_config))
        .route("/nginx/main-conf", get(nginx::get_main_conf))
        .route("/nginx/main-conf", put(nginx::save_main_conf))
        .route("/nginx/test", post(nginx::test_config))
        // 认证鉴权
        .route("/auth/check-init", get(auth::check_init))
        .route("/auth/init", post(auth::init_admin))
        .route("/auth/login", post(auth::login))
        // SSL 证书管理
        .route("/ssl/certs", get(ssl::list_certs))
        .route("/ssl/certs/upload", post(ssl::upload_cert))
        .route("/ssl/certs/request", post(ssl::request_cert))
        .route("/ssl/certs/renew/{domain}", post(ssl::renew_cert))
        .route("/ssl/certs/{domain}", delete(ssl::delete_cert))
        .route("/ssl/certs/{domain}/toggle-renew", post(ssl::toggle_auto_renew))
        .route("/ssl/domains", get(ssl::list_cert_domains))
        .route("/ssl/nginx-template/{domain}", get(ssl::nginx_ssl_template))
        .route("/ssl/acme/config", get(ssl::get_acme_config))
        .route("/ssl/acme/config", put(ssl::save_acme_config))
        // ACME 账号管理
        .route("/ssl/acme/accounts", get(ssl::list_acme_accounts))
        .route("/ssl/acme/accounts", post(ssl::add_acme_account))
        .route("/ssl/acme/accounts/{id}", put(ssl::update_acme_account))
        .route("/ssl/acme/accounts/{id}", delete(ssl::delete_acme_account))
        .route("/ssl/acme/accounts/{id}/set-default", post(ssl::set_default_acme_account))
        // DNS 凭证管理
        .route("/ssl/dns-credentials", get(ssl::list_dns_credentials))
        .route("/ssl/dns-credentials", post(ssl::add_dns_credential))
        .route("/ssl/dns-credentials/{id}", put(ssl::update_dns_credential))
        .route("/ssl/dns-credentials/{id}", delete(ssl::delete_dns_credential))
        .route("/ssl/dns-credentials/{id}/fields", get(ssl::get_dns_credential_json));

    // 前端静态文件目录
    let frontend_dir = "admin_frontend/dist";
    let fallback = ServeFile::new(format!("{}/index.html", frontend_dir));

    let app = Router::new()
        .nest("/api/v1", api_router)
        .layer(middleware::from_fn(auth::auth_middleware))
        .fallback_service(
            ServeDir::new(frontend_dir).not_found_service(fallback),
        )
        .with_state(state);

    let listener = TcpListener::bind(config::ADMIN_ADDR).await.unwrap();
    crate::log_daemon!("ADMIN_UI", "管理控制台启动成功，监听 http://{}", config::ADMIN_ADDR);
    crate::log_daemon!("ADMIN_UI", "API 端点: http://{}/api/v1/", config::ADMIN_ADDR);
    crate::log_daemon!("ADMIN_UI", "管理面板: http://{}/", config::ADMIN_ADDR);

    if let Err(e) = axum::serve(listener, app).await {
        crate::log_error!("ADMIN_UI", "管理 API 运行异常: {}", e);
    }
}
