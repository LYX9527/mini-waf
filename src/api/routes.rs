use crate::state::{AppState, Route, RouteType};
use axum::{extract::State, Json};
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[derive(Deserialize)]
pub struct AddRuleRequest {
    pub rule: String,
}

#[derive(Deserialize)]
pub struct AddRouteRequest {
    pub path_prefix: String,
    pub upstream: String,
    pub route_type: String, // "proxy" 或 "static"
    #[serde(default)]
    pub is_spa: bool,
}

#[derive(Deserialize)]
pub struct DeleteRouteRequest {
    pub path_prefix: String,
}

/// GET /rules: 获取当前所有拦截规则
pub async fn get_rules(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rules = state.rules.read().await;
    Json(serde_json::json!({ "rules": *rules }))
}

/// POST /rules: 动态添加一条新规则，并持久化到数据库
pub async fn add_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddRuleRequest>,
) -> Json<serde_json::Value> {
    let insert_result = sqlx::query!(
        "INSERT INTO rules (keyword, rule_type, status) VALUES (?, 'CUSTOM', 1)",
        payload.rule
    )
    .execute(&state.db_pool)
    .await;

    match insert_result {
        Ok(_) => {
            let mut rules = state.rules.write().await;
            if !rules.contains(&payload.rule) {
                rules.push(payload.rule.clone());
            }
            Json(serde_json::json!({
                "status": "success",
                "message": format!("WAF 规则 '{}' 已持久化并动态生效！", payload.rule)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("规则添加失败: {}", e)
        })),
    }
}

/// GET /routes: 列出所有路由
pub async fn get_routes(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let records = sqlx::query!("SELECT path_prefix, upstream, route_type, is_spa, status FROM routes ORDER BY LENGTH(path_prefix) DESC")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();
    
    let route_list: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "path_prefix": r.path_prefix,
                "upstream": r.upstream,
                "route_type": r.route_type,
                "is_spa": r.is_spa != 0,
                "is_active": r.status == 1,
            })
        })
        .collect();
    Json(serde_json::json!({ "routes": route_list }))
}

/// POST /routes: 添加一条新路由（支持 proxy 和 static 两种类型）
pub async fn add_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddRouteRequest>,
) -> Json<serde_json::Value> {
    let is_static = payload.route_type == "static";
    let rt = if is_static {
        "static"
    } else {
        "proxy"
    };

    // 静态路由：校验目录是否存在
    if is_static && !std::path::Path::new(&payload.upstream).is_dir() {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("静态资源目录不存在: {}", payload.upstream)
        }));
    }

    let insert_result = sqlx::query!(
        "INSERT INTO routes (path_prefix, upstream, route_type, is_spa, status) VALUES (?, ?, ?, ?, 1)",
        payload.path_prefix,
        payload.upstream,
        rt,
        payload.is_spa
    )
    .execute(&state.db_pool)
    .await;

    match insert_result {
        Ok(_) => {
            let new_route = Route {
                path_prefix: payload.path_prefix.clone(),
                upstream: payload.upstream,
                route_type: if is_static {
                    RouteType::Static
                } else {
                    RouteType::Proxy
                },
                is_spa: payload.is_spa,
            };
            let mut routes = state.routes.write().await;
            routes.push(new_route);
            routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
            Json(serde_json::json!({
                "status": "success",
                "message": format!("路由 '{}' 已添加（类型: {}）", payload.path_prefix, rt)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("路由添加失败: {}", e)
        })),
    }
}

/// DELETE /routes: 停用一条路由
pub async fn delete_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteRouteRequest>,
) -> Json<serde_json::Value> {
    let result = sqlx::query!(
        "UPDATE routes SET status = 0 WHERE path_prefix = ?",
        payload.path_prefix
    )
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            let mut routes = state.routes.write().await;
            routes.retain(|r| r.path_prefix != payload.path_prefix);
            Json(serde_json::json!({
                "status": "success",
                "message": format!("路由 '{}' 已停用", payload.path_prefix)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("路由停用失败: {}", e)
        })),
    }
}
#[derive(Deserialize)]
pub struct EnableRouteRequest {
    pub path_prefix: String,
}

/// POST /routes/enable: 启用一条路由
pub async fn enable_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EnableRouteRequest>,
) -> Json<serde_json::Value> {
    let result = sqlx::query!(
        "UPDATE routes SET status = 1 WHERE path_prefix = ?",
        payload.path_prefix
    )
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            if let Ok(Some(r)) = sqlx::query!("SELECT path_prefix, upstream, route_type, is_spa FROM routes WHERE path_prefix = ?", payload.path_prefix).fetch_optional(&state.db_pool).await {
                let mut routes = state.routes.write().await;
                if !routes.iter().any(|rt| rt.path_prefix == payload.path_prefix) {
                    routes.push(Route {
                        path_prefix: r.path_prefix.clone(),
                        upstream: r.upstream,
                        route_type: if r.route_type == "static" { crate::state::RouteType::Static } else { crate::state::RouteType::Proxy },
                        is_spa: r.is_spa != 0,
                    });
                    routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
                }
            }
            Json(serde_json::json!({
                "status": "success",
                "message": format!("路由 '{}' 已启用", payload.path_prefix)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("路由启用失败: {}", e)
        })),
    }
}

#[derive(Deserialize)]
pub struct HealthCheckRequest {
    pub upstream: String,
}

/// POST /routes/health-check: 测试反向代理目标的连通性
pub async fn health_check_route(
    Json(payload): Json<HealthCheckRequest>,
) -> Json<serde_json::Value> {
    // 3 秒超时尝试 TCP 连接
    let result = timeout(
        Duration::from_secs(3),
        TcpStream::connect(&payload.upstream),
    )
    .await;

    match result {
        Ok(Ok(_stream)) => {
            Json(serde_json::json!({ "reachable": true }))
        }
        Ok(Err(e)) => {
            Json(serde_json::json!({ "reachable": false, "error": e.to_string() }))
        }
        Err(_) => {
            Json(serde_json::json!({ "reachable": false, "error": "连接超时 (3s)" }))
        }
    }
}
