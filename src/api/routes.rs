use crate::state::{AppState, Route, RouteType};
use axum::{extract::State, Json};
use serde::Deserialize;
use std::sync::Arc;

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

/// GET /routes: 列出所有活跃路由
pub async fn get_routes(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let routes = state.routes.read().await;
    let route_list: Vec<serde_json::Value> = routes
        .iter()
        .map(|r| {
            serde_json::json!({
                "path_prefix": r.path_prefix,
                "upstream": r.upstream,
                "route_type": match r.route_type {
                    RouteType::Proxy => "proxy",
                    RouteType::Static => "static",
                },
                "is_spa": r.is_spa,
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
