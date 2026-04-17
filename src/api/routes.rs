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

/// GET /rules: 获取当前所有拦截规则
pub async fn get_rules(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rules = state.rules.read().await;
    let rules_json: Vec<serde_json::Value> = rules.iter().map(|r| {
        serde_json::json!({
            "keyword": r.keyword,
            "target_field": r.target_field,
            "match_type": r.match_type
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
        "INSERT INTO rules (keyword, rule_type, status, target_field, match_type) VALUES (?, 'CUSTOM', 1, ?, ?)",
        payload.rule,
        target_field,
        match_type
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
                    action: "Block".to_string(),
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

// ─── 内置默认规则集 ────────────────────────────────────────────────────────────
/// 返回 OWASP Top10 核心规则集（关键词、目标区域、匹配模式、描述）
fn builtin_default_rules() -> Vec<serde_json::Value> {
    vec![
        // SQL 注入
        serde_json::json!({"keyword":"' or '1'='1","target_field":"URL","match_type":"Contains","description":"SQL 注入 - 万能密码"}),
        serde_json::json!({"keyword":"union select","target_field":"URL","match_type":"Contains","description":"SQL 注入 - UNION 查询"}),
        serde_json::json!({"keyword":"drop table","target_field":"URL","match_type":"Contains","description":"SQL 注入 - DROP TABLE"}),
        serde_json::json!({"keyword":"insert into","target_field":"URL","match_type":"Contains","description":"SQL 注入 - INSERT"}),
        serde_json::json!({"keyword":"exec(","target_field":"URL","match_type":"Contains","description":"SQL 注入 - exec 函数"}),
        serde_json::json!({"keyword":"or 1=1","target_field":"URL","match_type":"Contains","description":"SQL 注入 - 永真条件"}),
        serde_json::json!({"keyword":"-- ","target_field":"URL","match_type":"Contains","description":"SQL 注入 - 注释符"}),
        serde_json::json!({"keyword":";select ","target_field":"URL","match_type":"Contains","description":"SQL 注入 - 堆叠查询"}),
        // XSS 跨站脚本
        serde_json::json!({"keyword":"<script","target_field":"URL","match_type":"Contains","description":"XSS - script 标签"}),
        serde_json::json!({"keyword":"javascript:","target_field":"URL","match_type":"Contains","description":"XSS - javascript: 伪协议"}),
        serde_json::json!({"keyword":"onerror=","target_field":"URL","match_type":"Contains","description":"XSS - onerror 事件"}),
        serde_json::json!({"keyword":"onload=","target_field":"URL","match_type":"Contains","description":"XSS - onload 事件"}),
        serde_json::json!({"keyword":"<img src=x","target_field":"URL","match_type":"Contains","description":"XSS - img src 注入"}),
        serde_json::json!({"keyword":"alert(","target_field":"URL","match_type":"Contains","description":"XSS - alert 弹窗"}),
        serde_json::json!({"keyword":"document.cookie","target_field":"URL","match_type":"Contains","description":"XSS - cookie 窃取"}),
        serde_json::json!({"keyword":"eval(","target_field":"URL","match_type":"Contains","description":"XSS/RCE - eval 执行"}),
        // 路径穿越
        serde_json::json!({"keyword":"../","target_field":"URL","match_type":"Contains","description":"路径穿越攻击"}),
        serde_json::json!({"keyword":"..\\","target_field":"URL","match_type":"Contains","description":"路径穿越攻击 (Windows)"}),
        serde_json::json!({"keyword":"%2e%2e%2f","target_field":"URL","match_type":"Contains","description":"路径穿越 - URL编码形式"}),
        serde_json::json!({"keyword":"/etc/passwd","target_field":"URL","match_type":"Contains","description":"路径穿越 - 读取 passwd"}),
        serde_json::json!({"keyword":"/etc/shadow","target_field":"URL","match_type":"Contains","description":"路径穿越 - 读取 shadow"}),
        serde_json::json!({"keyword":"c:\\windows","target_field":"URL","match_type":"Contains","description":"路径穿越 - Windows 系统路径"}),
        // RCE / 命令注入
        serde_json::json!({"keyword":"cmd.exe","target_field":"URL","match_type":"Contains","description":"RCE - Windows cmd"}),
        serde_json::json!({"keyword":"/bin/sh","target_field":"URL","match_type":"Contains","description":"RCE - Unix shell"}),
        serde_json::json!({"keyword":"/bin/bash","target_field":"URL","match_type":"Contains","description":"RCE - bash"}),
        serde_json::json!({"keyword":"wget http","target_field":"URL","match_type":"Contains","description":"RCE - wget 下载"}),
        serde_json::json!({"keyword":"curl http","target_field":"URL","match_type":"Contains","description":"RCE - curl 下载"}),
        serde_json::json!({"keyword":"phpinfo()","target_field":"URL","match_type":"Contains","description":"PHP 信息泄露"}),
        serde_json::json!({"keyword":"passthru(","target_field":"URL","match_type":"Contains","description":"PHP RCE - passthru"}),
        serde_json::json!({"keyword":"system(","target_field":"URL","match_type":"Contains","description":"PHP RCE - system"}),
        // SSRF 服务端请求伪造
        serde_json::json!({"keyword":"169.254.169.254","target_field":"URL","match_type":"Contains","description":"SSRF - AWS 元数据"}),
        serde_json::json!({"keyword":"metadata.google.internal","target_field":"URL","match_type":"Contains","description":"SSRF - GCP 元数据"}),
        serde_json::json!({"keyword":"file:///","target_field":"URL","match_type":"Contains","description":"SSRF - 本地文件读取"}),
        serde_json::json!({"keyword":"gopher://","target_field":"URL","match_type":"Contains","description":"SSRF - Gopher 协议"}),
        serde_json::json!({"keyword":"dict://","target_field":"URL","match_type":"Contains","description":"SSRF - Dict 协议"}),
        // Log4Shell / Log4j
        serde_json::json!({"keyword":"${jndi:","target_field":"URL","match_type":"Contains","description":"Log4Shell (CVE-2021-44228)"}),
        serde_json::json!({"keyword":"${jndi:","target_field":"Header","match_type":"Contains","description":"Log4Shell (Header 注入)"}),
        // 扫描器 / 恶意 UA
        serde_json::json!({"keyword":"sqlmap","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - sqlmap"}),
        serde_json::json!({"keyword":"nikto","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - Nikto"}),
        serde_json::json!({"keyword":"masscan","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - Masscan"}),
        serde_json::json!({"keyword":"nessus","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - Nessus"}),
        serde_json::json!({"keyword":"nmap","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - Nmap"}),
        serde_json::json!({"keyword":"acunetix","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - Acunetix"}),
        serde_json::json!({"keyword":"zgrab","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - zgrab"}),
        serde_json::json!({"keyword":"dirsearch","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - dirsearch"}),
        serde_json::json!({"keyword":"gobuster","target_field":"User-Agent","match_type":"Contains","description":"扫描器 - gobuster"}),
        // 敏感文件探测
        serde_json::json!({"keyword":"wp-admin","target_field":"URL","match_type":"Contains","description":"WordPress 后台探测"}),
        serde_json::json!({"keyword":".env","target_field":"URL","match_type":"Contains","description":"环境变量文件探测"}),
        serde_json::json!({"keyword":".git/","target_field":"URL","match_type":"Contains","description":"Git 仓库泄露探测"}),
        serde_json::json!({"keyword":"/.svn/","target_field":"URL","match_type":"Contains","description":"SVN 仓库泄露探测"}),
        serde_json::json!({"keyword":"phpmyadmin","target_field":"URL","match_type":"Contains","description":"phpMyAdmin 探测"}),
    ]
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
}
fn default_url() -> String { "URL".to_string() }
fn default_contains() -> String { "Contains".to_string() }

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
            "INSERT IGNORE INTO rules (keyword, rule_type, status, target_field, match_type) VALUES (?, 'CUSTOM', 1, ?, ?)"
        )
        .bind(&item.keyword)
        .bind(&item.target_field)
        .bind(&item.match_type)
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
                        action: "Block".to_string(),
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
