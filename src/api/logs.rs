use crate::state::AppState;
use axum::{extract::Query, extract::State, Json};
use serde::Deserialize;
use sqlx::Row;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct LogQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub ip: Option<String>,
    pub path: Option<String>,
    pub rule: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
}

/// GET /api/v1/logs/attacks — 分页攻击日志
pub async fn get_attack_logs(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LogQuery>,
) -> Json<serde_json::Value> {
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let mut where_clauses = vec!["1=1".to_string()];
    if let Some(ref ip) = q.ip {
        where_clauses.push(format!("ip_address LIKE '%{}%'", ip.replace('\'', "''")));
    }
    if let Some(ref path) = q.path {
        where_clauses.push(format!(
            "request_path LIKE '%{}%'",
            path.replace('\'', "''")
        ));
    }
    if let Some(ref rule) = q.rule {
        where_clauses.push(format!(
            "matched_rule LIKE '%{}%'",
            rule.replace('\'', "''")
        ));
    }
    if let Some(ref start) = q.start {
        where_clauses.push(format!("created_at >= '{}'", start));
    }
    if let Some(ref end) = q.end {
        where_clauses.push(format!("created_at <= '{}'", end));
    }

    let where_sql = where_clauses.join(" AND ");

    let count_query = format!("SELECT COUNT(*) as cnt FROM attack_logs WHERE {}", where_sql);
    let total: i64 = sqlx::query_scalar(&count_query)
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or(0);

    let data_query = format!(
        "SELECT ip_address, request_path, matched_rule, created_at FROM attack_logs \
         WHERE {} ORDER BY created_at DESC LIMIT {} OFFSET {}",
        where_sql, page_size, offset
    );
    let rows = sqlx::query(&data_query)
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "ip_address": row.get::<String, _>("ip_address"),
                "request_path": row.get::<String, _>("request_path"),
                "matched_rule": row.get::<String, _>("matched_rule"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").format("%Y-%m-%d %H:%M:%S").to_string(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": data,
    }))
}

/// GET /api/v1/logs/access — 分页访问日志
pub async fn get_access_logs(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LogQuery>,
) -> Json<serde_json::Value> {
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let mut where_clauses = vec!["1=1".to_string()];
    if let Some(ref ip) = q.ip {
        where_clauses.push(format!("ip_address LIKE '%{}%'", ip.replace('\'', "''")));
    }
    if let Some(ref path) = q.path {
        where_clauses.push(format!(
            "request_path LIKE '%{}%'",
            path.replace('\'', "''")
        ));
    }
    if let Some(ref start) = q.start {
        where_clauses.push(format!("created_at >= '{}'", start));
    }
    if let Some(ref end) = q.end {
        where_clauses.push(format!("created_at <= '{}'", end));
    }

    let where_sql = where_clauses.join(" AND ");

    let count_query = format!("SELECT COUNT(*) as cnt FROM access_logs WHERE {}", where_sql);
    let total: i64 = sqlx::query_scalar(&count_query)
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or(0);

    let data_query = format!(
        "SELECT ip_address, request_path, method, status_code, is_blocked, matched_rule, created_at \
         FROM access_logs WHERE {} ORDER BY created_at DESC LIMIT {} OFFSET {}",
        where_sql, page_size, offset
    );
    let rows = sqlx::query(&data_query)
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "ip_address": row.get::<String, _>("ip_address"),
                "request_path": row.get::<String, _>("request_path"),
                "method": row.get::<String, _>("method"),
                "status_code": row.get::<i32, _>("status_code"),
                "is_blocked": row.get::<i8, _>("is_blocked") != 0,
                "matched_rule": row.get::<Option<String>, _>("matched_rule"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").format("%Y-%m-%d %H:%M:%S").to_string(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": data,
    }))
}
