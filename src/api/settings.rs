use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Deserialize;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Arc;

/// GET /api/v1/settings — 获取所有系统设置
pub async fn get_settings(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = sqlx::query("SELECT setting_key, setting_value, description FROM system_settings")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();

    let mut settings = serde_json::Map::new();
    for row in rows {
        let key: String = row.get("setting_key");
        settings.insert(
            key.clone(),
            serde_json::json!({
                "value": row.get::<String, _>("setting_value"),
                "description": row.get::<Option<String>, _>("description"),
            }),
        );
    }

    Json(serde_json::json!({ "settings": settings }))
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    pub settings: HashMap<String, String>,
}

/// PUT /api/v1/settings — 批量更新系统设置
pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateSettingsRequest>,
) -> Json<serde_json::Value> {
    let mut updated = 0;
    let mut errors: Vec<String> = Vec::new();

    for (key, value) in &payload.settings {
        let result = sqlx::query("UPDATE system_settings SET setting_value = ? WHERE setting_key = ?")
            .bind(value)
            .bind(key)
            .execute(&state.db_pool)
            .await;

        match result {
            Ok(r) => {
                if r.rows_affected() > 0 {
                    updated += 1;
                    if key == "custom_block_page" {
                        let mut cache = state.custom_block_page.write().await;
                        *cache = value.clone();
                    }
                } else {
                    errors.push(format!("未知设置项: {}", key));
                }
            }
            Err(e) => errors.push(format!("{}: {}", key, e)),
        }
    }

    if errors.is_empty() {
        Json(serde_json::json!({
            "status": "success",
            "message": format!("已更新 {} 项设置", updated)
        }))
    } else {
        Json(serde_json::json!({
            "status": "partial",
            "message": format!("已更新 {} 项，{} 项失败", updated, errors.len()),
            "errors": errors
        }))
    }
}
