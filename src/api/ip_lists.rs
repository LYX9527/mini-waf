use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct IpEntry {
    pub ip_address: String,
    pub reason: Option<String>,
}

/// GET /api/v1/ip-lists/blacklist
pub async fn get_blacklist(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT ip_address, reason, created_at FROM ip_blacklist ORDER BY created_at DESC",
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "ip_address": r.get::<String, _>("ip_address"),
                "reason": r.get::<Option<String>, _>("reason"),
                "created_at": r
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at")
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()),
            })
        })
        .collect();

    Json(serde_json::json!({ "data": data }))
}

/// POST /api/v1/ip-lists/blacklist
pub async fn add_to_blacklist(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<IpEntry>,
) -> Json<serde_json::Value> {
    let result = sqlx::query(
        "INSERT IGNORE INTO ip_blacklist (ip_address, reason) VALUES (?, ?)",
    )
    .bind(&payload.ip_address)
    .bind(&payload.reason)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            state
                .ip_blacklist
                .write()
                .await
                .insert(payload.ip_address.clone());
            Json(serde_json::json!({
                "status": "success",
                "message": format!("IP {} 已加入黑名单", payload.ip_address)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("添加失败: {}", e)
        })),
    }
}

/// DELETE /api/v1/ip-lists/blacklist/:ip
pub async fn remove_from_blacklist(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Json<serde_json::Value> {
    let result = sqlx::query("DELETE FROM ip_blacklist WHERE ip_address = ?")
        .bind(&ip)
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(_) => {
            state.ip_blacklist.write().await.remove(&ip);
            Json(serde_json::json!({
                "status": "success",
                "message": format!("IP {} 已从黑名单移除", ip)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("删除失败: {}", e)
        })),
    }
}

/// GET /api/v1/ip-lists/whitelist
pub async fn get_whitelist(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT ip_address, reason, created_at FROM ip_whitelist ORDER BY created_at DESC",
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let data: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "ip_address": r.get::<String, _>("ip_address"),
                "reason": r.get::<Option<String>, _>("reason"),
                "created_at": r
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at")
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()),
            })
        })
        .collect();

    Json(serde_json::json!({ "data": data }))
}

/// POST /api/v1/ip-lists/whitelist
pub async fn add_to_whitelist(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<IpEntry>,
) -> Json<serde_json::Value> {
    let result = sqlx::query(
        "INSERT IGNORE INTO ip_whitelist (ip_address, reason) VALUES (?, ?)",
    )
    .bind(&payload.ip_address)
    .bind(&payload.reason)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            state
                .ip_whitelist
                .write()
                .await
                .insert(payload.ip_address.clone());
            Json(serde_json::json!({
                "status": "success",
                "message": format!("IP {} 已加入白名单", payload.ip_address)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("添加失败: {}", e)
        })),
    }
}

/// DELETE /api/v1/ip-lists/whitelist/:ip
pub async fn remove_from_whitelist(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Json<serde_json::Value> {
    let result = sqlx::query("DELETE FROM ip_whitelist WHERE ip_address = ?")
        .bind(&ip)
        .execute(&state.db_pool)
        .await;

    match result {
        Ok(_) => {
            state.ip_whitelist.write().await.remove(&ip);
            Json(serde_json::json!({
                "status": "success",
                "message": format!("IP {} 已从白名单移除", ip)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("删除失败: {}", e)
        })),
    }
}
