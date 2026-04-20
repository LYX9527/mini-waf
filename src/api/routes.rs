use crate::state::{AppState, Route, RouteType};
use axum::{extract::State, Json};
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[derive(Deserialize)]
pub struct AddRuleRequest {
    pub rule: String,
    pub target_field: Option<String>,
    pub match_type: Option<String>,
    pub action: Option<String>,
}

#[derive(Deserialize)]
pub struct DeleteRuleRequest {
    pub rule: String,
    pub target_field: String,
    pub match_type: String,
}

#[derive(Deserialize)]
pub struct EditRouteRequest {
    pub old_path_prefix: String,
    pub path_prefix: String,
    pub upstream: String,
    pub host_pattern: Option<String>,
    pub old_host_pattern: Option<String>,
}

#[derive(Deserialize)]
pub struct AddRouteRequest {
    pub path_prefix: String,
    pub upstream: String,
    pub host_pattern: Option<String>,
}

#[derive(Deserialize)]
pub struct RouteIdRequest {
    pub id: i64,
}

#[derive(Deserialize)]
pub struct EditRuleRequest {
    pub old_keyword: String,
    pub old_target_field: String,
    pub old_match_type: String,
    pub keyword: Option<String>,
    pub target_field: Option<String>,
    pub match_type: Option<String>,
    pub action: Option<String>,
}

#[derive(Deserialize)]
pub struct ToggleRuleRequest {
    pub keyword: String,
    pub target_field: String,
    pub match_type: String,
}

/// GET /rules: 获取当前所有拦截规则
pub async fn get_rules(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rules = state.rules.read().await;
    let rules_json: Vec<serde_json::Value> = rules.iter().map(|r| {
        serde_json::json!({
            "keyword": r.keyword,
            "target_field": r.target_field,
            "match_type": r.match_type,
            "action": r.action,
            "status": r.status,
            "hit_count": r.get_hit_count()
        })
    }).collect();
    Json(serde_json::json!({ "rules": rules_json }))
}

/// POST /rules: 动态添加一条新规则，并持久化到数据库
pub async fn add_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddRuleRequest>,
) -> Json<serde_json::Value> {
    let target_field = payload.target_field.unwrap_or_else(|| "URL".to_string());
    let match_type = payload.match_type.unwrap_or_else(|| "Contains".to_string());
    let action = payload.action.unwrap_or_else(|| "Block".to_string());

    // 校验正则表达式有效性
    let compiled_regex = if match_type == "Regex" {
        match regex::Regex::new(&payload.rule) {
            Ok(r) => Some(r),
            Err(e) => return Json(serde_json::json!({ "status": "error", "message": format!("正则表达式由于语法错误被拒绝: {}", e) })),
        }
    } else {
        None
    };

    let insert_result = sqlx::query!(
        "INSERT INTO rules (keyword, rule_type, status, target_field, match_type, action) VALUES (?, 'CUSTOM', 1, ?, ?, ?)",
        payload.rule,
        target_field,
        match_type,
        action
    )
    .execute(&state.db_pool)
    .await;

    match insert_result {
        Ok(_) => {
            let mut rules = state.rules.write().await;
            if !rules.iter().any(|r| r.keyword == payload.rule && r.target_field == target_field && r.match_type == match_type) {
                rules.push(crate::state::WafRule {
                    keyword: payload.rule.clone(),
                    target_field: target_field.clone(),
                    match_type: match_type.clone(),
                    rule_type: "CUSTOM".to_string(),
                    action: action.clone(),
                    status: 1,
                    hit_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    compiled_regex,
                });
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
/// DELETE /rules: 移除制定拦截规则
pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteRuleRequest>,
) -> Json<serde_json::Value> {
    let result = sqlx::query!(
        "DELETE FROM rules WHERE keyword = ? AND target_field = ? AND match_type = ?",
        payload.rule,
        payload.target_field,
        payload.match_type
    )
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            let mut rules = state.rules.write().await;
            rules.retain(|r| !(r.keyword == payload.rule && r.target_field == payload.target_field && r.match_type == payload.match_type));
            Json(serde_json::json!({
                "status": "success",
                "message": format!("WAF 规则 '{}' 已彻底删除", payload.rule)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("规则删除失败: {}", e)
        })),
    }
}

/// PUT /rules: 编辑现有规则
pub async fn edit_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EditRuleRequest>,
) -> Json<serde_json::Value> {
    let new_keyword = payload.keyword.as_deref().unwrap_or(&payload.old_keyword);
    let new_target = payload.target_field.as_deref().unwrap_or(&payload.old_target_field);
    let new_match = payload.match_type.as_deref().unwrap_or(&payload.old_match_type);
    let new_action = payload.action.as_deref().unwrap_or("Block");

    // 校验新正则
    if new_match == "Regex" {
        if regex::Regex::new(new_keyword).is_err() {
            return Json(serde_json::json!({ "status": "error", "message": "无效的正则表达式" }));
        }
    }

    let result = sqlx::query(
        "UPDATE rules SET keyword = ?, target_field = ?, match_type = ?, action = ? WHERE keyword = ? AND target_field = ? AND match_type = ?"
    )
    .bind(new_keyword)
    .bind(new_target)
    .bind(new_match)
    .bind(new_action)
    .bind(&payload.old_keyword)
    .bind(&payload.old_target_field)
    .bind(&payload.old_match_type)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            let compiled_regex = if new_match == "Regex" {
                regex::Regex::new(new_keyword).ok()
            } else { None };

            let mut rules = state.rules.write().await;
            if let Some(rule) = rules.iter_mut().find(|r| {
                r.keyword == payload.old_keyword && r.target_field == payload.old_target_field && r.match_type == payload.old_match_type
            }) {
                rule.keyword = new_keyword.to_string();
                rule.target_field = new_target.to_string();
                rule.match_type = new_match.to_string();
                rule.action = new_action.to_string();
                rule.compiled_regex = compiled_regex;
            }
            Json(serde_json::json!({ "status": "success", "message": "规则已更新" }))
        }
        Ok(_) => Json(serde_json::json!({ "status": "error", "message": "未找到要更新的规则" })),
        Err(e) => Json(serde_json::json!({ "status": "error", "message": format!("规则更新失败: {}", e) })),
    }
}

/// POST /rules/toggle: 停用/启用规则
pub async fn toggle_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ToggleRuleRequest>,
) -> Json<serde_json::Value> {
    // 查当前状态
    let current_status = {
        let rules = state.rules.read().await;
        rules.iter().find(|r| {
            r.keyword == payload.keyword && r.target_field == payload.target_field && r.match_type == payload.match_type
        }).map(|r| r.status)
    };

    let new_status: i8 = match current_status {
        Some(1) => 0,
        Some(0) => 1,
        _ => {
            // 内存中没有（可能已停用且未加载），尝试从 DB 查
            let row = sqlx::query("SELECT status FROM rules WHERE keyword = ? AND target_field = ? AND match_type = ?")
                .bind(&payload.keyword)
                .bind(&payload.target_field)
                .bind(&payload.match_type)
                .fetch_optional(&state.db_pool)
                .await
                .ok()
                .flatten();
            match row {
                Some(r) => {
                    use sqlx::Row;
                    let s: i8 = r.get("status");
                    if s == 1 { 0 } else { 1 }
                }
                None => return Json(serde_json::json!({ "status": "error", "message": "规则未找到" })),
            }
        }
    };

    let _ = sqlx::query("UPDATE rules SET status = ? WHERE keyword = ? AND target_field = ? AND match_type = ?")
        .bind(new_status)
        .bind(&payload.keyword)
        .bind(&payload.target_field)
        .bind(&payload.match_type)
        .execute(&state.db_pool)
        .await;

    let mut rules = state.rules.write().await;
    if new_status == 0 {
        // 停用：在内存中标记 status=0
        if let Some(rule) = rules.iter_mut().find(|r| {
            r.keyword == payload.keyword && r.target_field == payload.target_field && r.match_type == payload.match_type
        }) {
            rule.status = 0;
        }
    } else {
        // 启用：如果内存中已有则设 status=1，否则从 DB 加载
        if let Some(rule) = rules.iter_mut().find(|r| {
            r.keyword == payload.keyword && r.target_field == payload.target_field && r.match_type == payload.match_type
        }) {
            rule.status = 1;
        } else {
            let compiled_regex = if payload.match_type == "Regex" {
                regex::Regex::new(&payload.keyword).ok()
            } else { None };
            rules.push(crate::state::WafRule {
                keyword: payload.keyword.clone(),
                target_field: payload.target_field.clone(),
                match_type: payload.match_type.clone(),
                rule_type: "CUSTOM".to_string(),
                action: "Block".to_string(),
                status: 1,
                hit_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                compiled_regex,
            });
        }
    }

    let action_text = if new_status == 1 { "启用" } else { "停用" };
    Json(serde_json::json!({
        "status": "success",
        "message": format!("规则已{}", action_text),
        "new_status": new_status
    }))
}

// ─── 内置默认规则集 ────────────────────────────────────────────────────────────
/// 返回完整的 OWASP + 现代攻击检测规则集（委托给独立模块）
fn builtin_default_rules() -> Vec<serde_json::Value> {
    crate::builtin_rules::builtin_default_rules()
}

#[derive(serde::Deserialize)]
pub struct ImportRulesRequest {
    pub rules: Vec<ImportRuleItem>,
    /// 是否先清空所有现有规则（默认 false = 合并）
    #[serde(default)]
    pub replace_all: bool,
}

#[derive(serde::Deserialize)]
pub struct ImportRuleItem {
    pub keyword: String,
    #[serde(default = "default_url")]
    pub target_field: String,
    #[serde(default = "default_contains")]
    pub match_type: String,
    #[serde(default = "default_block")]
    pub action: String,
}
fn default_url() -> String { "URL".to_string() }
fn default_contains() -> String { "Contains".to_string() }
fn default_block() -> String { "Block".to_string() }

/// POST /rules/import — 批量导入规则（JSON 数组，可选 replace_all）
pub async fn import_rules(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ImportRulesRequest>,
) -> Json<serde_json::Value> {
    if payload.replace_all {
        // 先清空数据库和内存（仅删除 CUSTOM 类型规则）
        let _ = sqlx::query("DELETE FROM rules WHERE rule_type = 'CUSTOM'")
            .execute(&state.db_pool)
            .await;
        let mut rules = state.rules.write().await;
        rules.retain(|r| r.rule_type != "CUSTOM");
        drop(rules);
    }

    let mut inserted = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for item in &payload.rules {
        if item.keyword.trim().is_empty() { skipped += 1; continue; }

        let compiled_regex = if item.match_type == "Regex" {
            match regex::Regex::new(&item.keyword) {
                Ok(r) => Some(r),
                Err(e) => { errors.push(format!("'{}' 正则错误: {}", item.keyword, e)); continue; }
            }
        } else { None };

        let res = sqlx::query(
            "INSERT IGNORE INTO rules (keyword, rule_type, status, target_field, match_type, action) VALUES (?, 'CUSTOM', 1, ?, ?, ?)"
        )
        .bind(&item.keyword)
        .bind(&item.target_field)
        .bind(&item.match_type)
        .bind(&item.action)
        .execute(&state.db_pool)
        .await;

        match res {
            Ok(r) if r.rows_affected() > 0 => {
                let mut rules = state.rules.write().await;
                if !rules.iter().any(|r| r.keyword == item.keyword && r.target_field == item.target_field && r.match_type == item.match_type) {
                    rules.push(crate::state::WafRule {
                        keyword: item.keyword.clone(),
                        target_field: item.target_field.clone(),
                        match_type: item.match_type.clone(),
                        rule_type: "CUSTOM".to_string(),
                        action: item.action.clone(),
                        status: 1,
                        hit_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        compiled_regex,
                    });
                }
                inserted += 1;
            }
            Ok(_) => { skipped += 1; } // 重复
            Err(e) => { errors.push(format!("'{}': {}", item.keyword, e)); }
        }
    }

    Json(serde_json::json!({
        "status": if errors.is_empty() { "success" } else { "partial" },
        "message": format!("导入完成: 新增 {} 条，跳过 {} 条，失败 {} 条", inserted, skipped, errors.len()),
        "inserted": inserted,
        "skipped": skipped,
        "errors": errors
    }))
}

/// GET /rules/export — 导出所有规则为 JSON
pub async fn export_rules(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rules = state.rules.read().await;
    let export: Vec<serde_json::Value> = rules.iter().map(|r| serde_json::json!({
        "keyword": r.keyword,
        "target_field": r.target_field,
        "match_type": r.match_type,
        "action": r.action,
    })).collect();
    Json(serde_json::json!({ "rules": export, "count": export.len() }))
}

/// POST /rules/load-defaults — 加载内置默认规则集（跳过已存在的）
pub async fn load_default_rules(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let defaults = builtin_default_rules();
    let mut inserted = 0usize;
    let mut skipped = 0usize;

    for item in &defaults {
        let keyword = item["keyword"].as_str().unwrap_or("");
        let target = item["target_field"].as_str().unwrap_or("URL");
        let mtype = item["match_type"].as_str().unwrap_or("Contains");

        if keyword.is_empty() { continue; }

        let compiled_regex = if mtype == "Regex" {
            regex::Regex::new(keyword).ok()
        } else { None };

        let res = sqlx::query(
            "INSERT IGNORE INTO rules (keyword, rule_type, status, target_field, match_type) VALUES (?, 'DEFAULT', 1, ?, ?)"
        )
        .bind(keyword)
        .bind(target)
        .bind(mtype)
        .execute(&state.db_pool)
        .await;

        match res {
            Ok(r) if r.rows_affected() > 0 => {
                let mut rules = state.rules.write().await;
                if !rules.iter().any(|r| r.keyword == keyword && r.target_field == target && r.match_type == mtype) {
                    rules.push(crate::state::WafRule {
                        keyword: keyword.to_string(),
                        target_field: target.to_string(),
                        match_type: mtype.to_string(),
                        rule_type: "DEFAULT".to_string(),
                        action: "Block".to_string(),
                        status: 1,
                        hit_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        compiled_regex,
                    });
                }
                inserted += 1;
            }
            _ => { skipped += 1; }
        }
    }

    Json(serde_json::json!({
        "status": "success",
        "message": format!("默认规则集加载完成: 新增 {} 条，已存在跳过 {} 条", inserted, skipped),
        "inserted": inserted,
        "skipped": skipped,
        "total_defaults": defaults.len()
    }))
}

/// GET /rules/defaults — 预览内置默认规则列表（不写入）
pub async fn get_default_rules() -> Json<serde_json::Value> {
    let defaults = builtin_default_rules();
    Json(serde_json::json!({ "rules": defaults, "count": defaults.len() }))
}

/// GET /routes: 列出所有路由
pub async fn get_routes(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let records = sqlx::query!("SELECT id, path_prefix, host_pattern, upstream, route_type, status FROM routes ORDER BY host_pattern IS NULL ASC, LENGTH(path_prefix) DESC")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();
    
    let route_list: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "path_prefix": r.path_prefix,
                "host_pattern": r.host_pattern,
                "upstream": r.upstream,
                "route_type": r.route_type,
                "is_active": r.status == 1,
            })
        })
        .collect();
    Json(serde_json::json!({ "routes": route_list }))
}

/// POST /routes: 添加一条新路由
pub async fn add_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddRouteRequest>,
) -> Json<serde_json::Value> {
    let insert_result = sqlx::query!(
        "INSERT INTO routes (path_prefix, host_pattern, upstream, route_type, is_spa, status) VALUES (?, ?, ?, 'proxy', 0, 1)",
        payload.path_prefix,
        payload.host_pattern,
        payload.upstream,
    )
    .execute(&state.db_pool)
    .await;

    match insert_result {
        Ok(_) => {
            let new_route = Route {
                path_prefix: payload.path_prefix.clone(),
                host_pattern: payload.host_pattern,
                upstream: payload.upstream,
                route_type: RouteType::Proxy,
                rate_limit_threshold: None,
                health_check_path: None,
                rr_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let mut routes = state.routes.write().await;
            routes.push(new_route);
            routes.sort_by(|a, b| {
                match (a.host_pattern.is_some(), b.host_pattern.is_some()) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => b.path_prefix.len().cmp(&a.path_prefix.len()),
                }
            });
            Json(serde_json::json!({
                "status": "success",
                "message": format!("路由 '{}' 已添加", payload.path_prefix)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("路由添加失败: {}", e)
        })),
    }
}

/// POST /routes/disable: 停用一条路由
pub async fn disable_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RouteIdRequest>,
) -> Json<serde_json::Value> {
    // 先查出该路由的 path_prefix 和 host_pattern，用于后续清理内存
    let route_info = sqlx::query!("SELECT path_prefix, host_pattern FROM routes WHERE id = ?", payload.id)
        .fetch_optional(&state.db_pool)
        .await
        .ok()
        .flatten();

    let result = sqlx::query!("UPDATE routes SET status = 0 WHERE id = ?", payload.id)
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(_) => {
            if let Some(r) = route_info {
                let mut routes = state.routes.write().await;
                routes.retain(|rt| {
                    !(rt.path_prefix == r.path_prefix && rt.host_pattern == r.host_pattern)
                });
            }
            Json(serde_json::json!({
                "status": "success",
                "message": "路由已停用"
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("路由停用失败: {}", e)
        })),
    }
}

/// DELETE /routes: 彻底删除一条路由
pub async fn real_delete_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RouteIdRequest>,
) -> Json<serde_json::Value> {
    let route_info = sqlx::query!("SELECT path_prefix, host_pattern FROM routes WHERE id = ?", payload.id)
        .fetch_optional(&state.db_pool)
        .await
        .ok()
        .flatten();

    let result = sqlx::query!("DELETE FROM routes WHERE id = ?", payload.id)
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(_) => {
            if let Some(r) = route_info {
                let mut routes = state.routes.write().await;
                routes.retain(|rt| {
                    !(rt.path_prefix == r.path_prefix && rt.host_pattern == r.host_pattern)
                });
            }
            Json(serde_json::json!({
                "status": "success",
                "message": "路由已删除"
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("路由删除失败: {}", e)
        })),
    }
}
#[derive(Deserialize)]
pub struct EnableRouteRequest {
    pub id: i64,
}

/// POST /routes/enable: 启用一条路由
pub async fn enable_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EnableRouteRequest>,
) -> Json<serde_json::Value> {
    let result = sqlx::query!("UPDATE routes SET status = 1 WHERE id = ?", payload.id)
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(_) => {
            if let Ok(Some(r)) = sqlx::query!("SELECT path_prefix, host_pattern, upstream, route_type, rate_limit_threshold FROM routes WHERE id = ?", payload.id).fetch_optional(&state.db_pool).await {
                let mut routes = state.routes.write().await;
                let already = routes.iter().any(|rt| rt.path_prefix == r.path_prefix && rt.host_pattern == r.host_pattern);
                if !already {
                    routes.push(Route {
                        path_prefix: r.path_prefix.clone(),
                        host_pattern: r.host_pattern,
                        upstream: r.upstream,
                        route_type: RouteType::Proxy,
                        rate_limit_threshold: r.rate_limit_threshold,
                        health_check_path: None,
                        rr_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    });
                    routes.sort_by(|a, b| {
                        match (a.host_pattern.is_some(), b.host_pattern.is_some()) {
                            (true, false) => std::cmp::Ordering::Less,
                            (false, true) => std::cmp::Ordering::Greater,
                            _ => b.path_prefix.len().cmp(&a.path_prefix.len()),
                        }
                    });
                }
            }
            Json(serde_json::json!({
                "status": "success",
                "message": "路由已启用"
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
    let start_time = std::time::Instant::now();
    // 3 秒超时尝试 TCP 连接
    let result = timeout(
        Duration::from_secs(3),
        TcpStream::connect(&payload.upstream),
    )
    .await;
    let latency = start_time.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(_stream)) => {
            Json(serde_json::json!({ "reachable": true, "latency_ms": latency }))
        }
        Ok(Err(e)) => {
            Json(serde_json::json!({ "reachable": false, "error": e.to_string(), "latency_ms": latency }))
        }
        Err(_) => {
            Json(serde_json::json!({ "reachable": false, "error": "连接超时 (3s)" }))
        }
    }
}

/// PUT /routes/edit: 编辑现有路由
pub async fn edit_route(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EditRouteRequest>,
) -> Json<serde_json::Value> {
    let update_result = if let Some(ref old_host) = payload.old_host_pattern {
        sqlx::query!(
            "UPDATE routes SET path_prefix = ?, host_pattern = ?, upstream = ?, route_type = 'proxy' WHERE path_prefix = ? AND host_pattern = ?",
            payload.path_prefix,
            payload.host_pattern,
            payload.upstream,
            payload.old_path_prefix,
            old_host
        )
        .execute(&state.db_pool)
        .await
    } else {
        sqlx::query!(
            "UPDATE routes SET path_prefix = ?, host_pattern = ?, upstream = ?, route_type = 'proxy' WHERE path_prefix = ? AND host_pattern IS NULL",
            payload.path_prefix,
            payload.host_pattern,
            payload.upstream,
            payload.old_path_prefix
        )
        .execute(&state.db_pool)
        .await
    };

    match update_result {
        Ok(result) if result.rows_affected() > 0 => {
            let mut routes = state.routes.write().await;
            routes.retain(|r| !(r.path_prefix == payload.old_path_prefix && r.host_pattern == payload.old_host_pattern));
            
            // fetch old rate limit threshold
            let old_threshold = sqlx::query!("SELECT rate_limit_threshold FROM routes WHERE path_prefix = ?", payload.path_prefix)
                .fetch_optional(&state.db_pool)
                .await
                .ok().flatten().map(|r| r.rate_limit_threshold).flatten();

            let new_route = Route {
                path_prefix: payload.path_prefix.clone(),
                host_pattern: payload.host_pattern,
                upstream: payload.upstream,
                route_type: RouteType::Proxy,
                rate_limit_threshold: old_threshold,
                health_check_path: None,
                rr_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            routes.push(new_route);
            routes.sort_by(|a, b| {
                match (a.host_pattern.is_some(), b.host_pattern.is_some()) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => b.path_prefix.len().cmp(&a.path_prefix.len()),
                }
            });
            
            Json(serde_json::json!({
                "status": "success",
                "message": format!("路由 '{}' 已更新", payload.path_prefix)
            }))
        }
        Ok(_) => Json(serde_json::json!({
            "status": "error",
            "message": "未找到要更新的路由记录"
        })),
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("路由更新失败: {}", e)
        })),
    }
}
