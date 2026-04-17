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
                    match key.as_str() {
                        "custom_block_page" => {
                            let mut cache = state.custom_block_page.write().await;
                            *cache = value.clone();
                        }
                        "geo_blocked_countries" => {
                            // 解析逗号分隔的 ISO 国家代码，写入内存
                            let new_set: std::collections::HashSet<String> = value
                                .split(',')
                                .filter(|s| !s.trim().is_empty())
                                .map(|s| s.trim().to_uppercase())
                                .collect();
                            let mut blocked = state.geo_blocked_countries.write().await;
                            *blocked = new_set;
                        }
                        "rate_limit_threshold" => {
                            if let Ok(v) = value.parse() {
                                let mut s = state.settings.write().await;
                                s.rate_limit_threshold = v;
                            }
                        }
                        "penalty_ban_score" => {
                            if let Ok(v) = value.parse() {
                                let mut s = state.settings.write().await;
                                s.penalty_ban_score = v;
                            }
                        }
                        "penalty_attack_score" => {
                            if let Ok(v) = value.parse() {
                                let mut s = state.settings.write().await;
                                s.penalty_attack_score = v;
                            }
                        }
                        "trust_upstream_proxy" => {
                            let mut s = state.settings.write().await;
                            s.trust_upstream_proxy = value == "1" || value.to_lowercase() == "true";
                        }
                        "captcha_ttl_secs" => {
                            if let Ok(v) = value.parse() {
                                {
                                    let mut s = state.settings.write().await;
                                    s.captcha_ttl_secs = v;
                                }
                                *state.captcha_answers.write().await = moka::sync::Cache::builder()
                                    .time_to_live(std::time::Duration::from_secs(v))
                                    .build();
                            }
                        }
                        "token_ttl_secs" => {
                            if let Ok(v) = value.parse() {
                                {
                                    let mut s = state.settings.write().await;
                                    s.token_ttl_secs = v;
                                }
                                *state.verified_tokens.write().await = moka::sync::Cache::builder()
                                    .time_to_live(std::time::Duration::from_secs(v))
                                    .build();
                            }
                        }
                        "rate_limit_window_secs" => {
                            if let Ok(v) = value.parse() {
                                {
                                    let mut s = state.settings.write().await;
                                    s.rate_limit_window_secs = v;
                                }
                                *state.rate_limiter.write().await = moka::sync::Cache::builder()
                                    .time_to_live(std::time::Duration::from_secs(v))
                                    .build();
                            }
                        }
                        "penalty_ttl_secs" => {
                            if let Ok(v) = value.parse() {
                                {
                                    let mut s = state.settings.write().await;
                                    s.penalty_ttl_secs = v;
                                }
                                *state.penalty_box.write().await = moka::sync::Cache::builder()
                                    .time_to_live(std::time::Duration::from_secs(v))
                                    .build();
                            }
                        }
                        _ => {}
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
