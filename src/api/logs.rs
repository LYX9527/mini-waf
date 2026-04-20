use crate::state::AppState;
use axum::{extract::Query, extract::State, Json};
use serde::Deserialize;
use sqlx::{Row, QueryBuilder, MySql};
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

    let mut count_qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT COUNT(*) FROM attack_logs WHERE 1=1");
    let mut data_qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT ip_address, request_path, matched_rule, created_at FROM attack_logs WHERE 1=1");

    let apply_filters = |qb: &mut QueryBuilder<MySql>| {
        if let Some(ref ip) = q.ip {
            qb.push(" AND ip_address LIKE ");
            qb.push_bind(format!("%{}%", ip));
        }
        if let Some(ref path) = q.path {
            qb.push(" AND request_path LIKE ");
            qb.push_bind(format!("%{}%", path));
        }
        if let Some(ref rule) = q.rule {
            qb.push(" AND matched_rule LIKE ");
            qb.push_bind(format!("%{}%", rule));
        }
        if let Some(ref start) = q.start {
            qb.push(" AND created_at >= ");
            qb.push_bind(start.clone());
        }
        if let Some(ref end) = q.end {
            qb.push(" AND created_at <= ");
            qb.push_bind(end.clone());
        }
    };

    apply_filters(&mut count_qb);
    apply_filters(&mut data_qb);

    let total: i64 = count_qb.build_query_scalar()
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or(0);

    data_qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(page_size)
        .push(" OFFSET ")
        .push_bind(offset);

    let rows = data_qb.build()
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

    let mut count_qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT COUNT(*) FROM access_logs WHERE 1=1");
    let mut data_qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT ip_address, request_path, method, status_code, is_blocked, matched_rule, created_at, country, city FROM access_logs WHERE 1=1");

    let apply_filters = |qb: &mut QueryBuilder<MySql>| {
        if let Some(ref ip) = q.ip {
            qb.push(" AND ip_address LIKE ");
            qb.push_bind(format!("%{}%", ip));
        }
        if let Some(ref path) = q.path {
            qb.push(" AND request_path LIKE ");
            qb.push_bind(format!("%{}%", path));
        }
        if let Some(ref start) = q.start {
            qb.push(" AND created_at >= ");
            qb.push_bind(start.clone());
        }
        if let Some(ref end) = q.end {
            qb.push(" AND created_at <= ");
            qb.push_bind(end.clone());
        }
    };

    apply_filters(&mut count_qb);
    apply_filters(&mut data_qb);

    let total: i64 = count_qb.build_query_scalar()
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or(0);

    data_qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(page_size)
        .push(" OFFSET ")
        .push_bind(offset);

    let rows = data_qb.build()
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
                "country": row.get::<Option<String>, _>("country"),
                "city": row.get::<Option<String>, _>("city"),
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
