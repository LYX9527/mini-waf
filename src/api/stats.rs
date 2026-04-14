use crate::state::AppState;
use axum::{extract::State, Json};
use sqlx::Row;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// GET /api/v1/stats/realtime — 实时统计数据
pub async fn get_realtime_stats(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let uptime = state.counters.start_time.elapsed().as_secs();
    let total = state.counters.total_requests_today.load(Ordering::Relaxed);
    let blocked = state.counters.blocked_requests_today.load(Ordering::Relaxed);
    let active = state.rate_limiter.iter().count() as u64;

    Json(serde_json::json!({
        "total_requests": total,
        "blocked_attacks": blocked,
        "active_connections": active,
        "uptime_seconds": uptime,
    }))
}

/// GET /api/v1/stats/today — 今日按小时的请求/攻击趋势
pub async fn get_today_stats(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT HOUR(created_at) as hour, COUNT(*) as total, \
         CAST(SUM(is_blocked) AS UNSIGNED) as blocked \
         FROM access_logs WHERE DATE(created_at) = CURDATE() \
         GROUP BY HOUR(created_at) ORDER BY hour"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let mut hours: Vec<u32> = Vec::new();
    let mut requests: Vec<u64> = Vec::new();
    let mut blocked: Vec<u64> = Vec::new();

    for row in &rows {
        hours.push(row.get::<i32, _>("hour") as u32);
        requests.push(row.get::<i64, _>("total") as u64);
        blocked.push(row.get::<u64, _>("blocked"));
    }

    // 补齐缺失的小时
    for h in 0..24u32 {
        if !hours.contains(&h) {
            if let Some(pos) = hours.iter().position(|&x| x > h) {
                hours.insert(pos, h);
                requests.insert(pos, 0);
                blocked.insert(pos, 0);
            } else {
                hours.push(h);
                requests.push(0);
                blocked.push(0);
            }
        }
    }

    Json(serde_json::json!({
        "hours": hours,
        "requests": requests,
        "blocked": blocked,
    }))
}

/// GET /api/v1/stats/top-ips — Top 5 攻击来源 IP
pub async fn get_top_ips(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT ip_address, COUNT(*) as cnt FROM access_logs \
         WHERE is_blocked = 1 AND DATE(created_at) = CURDATE() \
         GROUP BY ip_address ORDER BY cnt DESC LIMIT 5"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "ip": r.get::<String, _>("ip_address"),
                "count": r.get::<i64, _>("cnt"),
            })
        })
        .collect();

    Json(serde_json::json!({ "data": data }))
}

/// GET /api/v1/stats/top-rules — Top 5 触发规则
pub async fn get_top_rules(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT matched_rule, COUNT(*) as cnt FROM access_logs \
         WHERE is_blocked = 1 AND matched_rule IS NOT NULL \
           AND DATE(created_at) = CURDATE() \
         GROUP BY matched_rule ORDER BY cnt DESC LIMIT 5"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "rule": r.get::<String, _>("matched_rule"),
                "count": r.get::<i64, _>("cnt"),
            })
        })
        .collect();

    Json(serde_json::json!({ "data": data }))
}
