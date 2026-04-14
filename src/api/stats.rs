use crate::state::AppState;
use axum::{extract::State, Json};
use sqlx::Row;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// GET /api/v1/stats/realtime — 基础实时统计（保留兼容）
pub async fn get_realtime_stats(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let uptime = state.counters.start_time.elapsed().as_secs();
    let total = state.counters.total_requests_today.load(Ordering::Relaxed);
    let blocked = state.counters.blocked_requests_today.load(Ordering::Relaxed);
    let active = state.rate_limiter.iter().count() as u64;

    // QPS 滑动窗口计算
    let qps = {
        let window = state.counters.qps_window.read().await;
        if window.len() < 2 {
            0.0
        } else {
            let front = window.front().unwrap();
            let back = window.back().unwrap();
            let elapsed = back.0.duration_since(front.0).as_secs_f64();
            if elapsed > 0.0 {
                (back.1 - front.1) as f64 / elapsed
            } else {
                0.0
            }
        }
    };

    Json(serde_json::json!({
        "total_requests": total,
        "blocked_attacks": blocked,
        "active_connections": active,
        "uptime_seconds": uptime,
        "qps": (qps * 10.0).round() / 10.0,
    }))
}

/// GET /api/v1/stats/overview — 今日汇总统计
pub async fn get_overview_stats(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM access_logs WHERE DATE(created_at) = CURDATE()",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);

    let unique_ips: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT ip_address) FROM access_logs WHERE DATE(created_at) = CURDATE()",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);

    let unique_visitors: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT CONCAT(ip_address, user_agent)) FROM access_logs WHERE DATE(created_at) = CURDATE()",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);

    let blocked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM access_logs WHERE is_blocked = 1 AND DATE(created_at) = CURDATE()",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);

    let err_4xx: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM access_logs WHERE status_code >= 400 AND status_code < 500 AND DATE(created_at) = CURDATE()",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);

    let err_5xx: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM access_logs WHERE status_code >= 500 AND DATE(created_at) = CURDATE()",
    )
    .fetch_one(&state.db_pool)
    .await
    .unwrap_or(0);

    let rate_4xx = if total > 0 {
        (err_4xx as f64 / total as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };
    let rate_5xx = if total > 0 {
        (err_5xx as f64 / total as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let qps = {
        let window = state.counters.qps_window.read().await;
        if window.len() < 2 {
            0.0
        } else {
            let front = window.front().unwrap();
            let back = window.back().unwrap();
            let elapsed = back.0.duration_since(front.0).as_secs_f64();
            if elapsed > 0.0 {
                (back.1 - front.1) as f64 / elapsed
            } else {
                0.0
            }
        }
    };

    Json(serde_json::json!({
        "total_requests": total,
        "unique_ips": unique_ips,
        "unique_visitors": unique_visitors,
        "blocked_attacks": blocked,
        "err_4xx": err_4xx,
        "err_4xx_rate": rate_4xx,
        "err_5xx": err_5xx,
        "err_5xx_rate": rate_5xx,
        "qps": (qps * 10.0).round() / 10.0,
    }))
}

/// GET /api/v1/stats/status-distribution — 响应状态码分布
pub async fn get_status_distribution(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT status_code, COUNT(*) as cnt FROM access_logs \
         WHERE DATE(created_at) = CURDATE() \
         GROUP BY status_code ORDER BY cnt DESC"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "status_code": r.get::<i32, _>("status_code"),
                "count": r.get::<i64, _>("cnt"),
            })
        })
        .collect();

    Json(serde_json::json!({ "data": data }))
}

/// GET /api/v1/stats/top-referers — Top 10 Referer 来源
pub async fn get_top_referers(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT referer, COUNT(*) as cnt FROM access_logs \
         WHERE DATE(created_at) = CURDATE() AND referer IS NOT NULL AND referer != '' \
         GROUP BY referer ORDER BY cnt DESC LIMIT 10"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let referer: String = r.get("referer");
            // 截取域名部分
            let domain = referer
                .split('/')
                .nth(2)
                .unwrap_or(&referer)
                .to_string();
            serde_json::json!({
                "referer": domain,
                "full": referer,
                "count": r.get::<i64, _>("cnt"),
            })
        })
        .collect();

    Json(serde_json::json!({ "data": data }))
}

/// GET /api/v1/stats/ip-geo — IP 地理位置统计（直接通过本地 MMDB 解析）
pub async fn get_ip_geo(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT ip_address, COUNT(*) as cnt FROM access_logs \
         WHERE DATE(created_at) = CURDATE() \
         GROUP BY ip_address ORDER BY cnt DESC LIMIT 50"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let ip_str: String = r.get("ip_address");
            let count: i64 = r.get("cnt");
            
            let mut lat: Option<f64> = None;
            let mut lng: Option<f64> = None;
            let mut country: Option<String> = None;
            let mut city: Option<String> = None;

            if let Some(ref db) = state.geo_db {
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    if let Ok(city_data) = db.lookup::<maxminddb::geoip2::City>(ip) {
                        if let Some(ref loc) = city_data.location {
                            lat = loc.latitude;
                            lng = loc.longitude;
                        }
                        if let Some(ref c) = city_data.country {
                            country = c.iso_code.map(|s| s.to_string());
                        }
                        if let Some(ref c) = city_data.city {
                            if let Some(ref names) = c.names {
                                city = names.get("zh-CN")
                                    .or_else(|| names.get("en"))
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                }
            }

            serde_json::json!({
                "ip": ip_str,
                "count": count,
                "lat": lat,
                "lng": lng,
                "country": country,
                "city": city,
            })
        })
        .collect();

    Json(serde_json::json!({ "data": data }))
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
