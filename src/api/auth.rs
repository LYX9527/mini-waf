use crate::state::AppState;
use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

/// GET /api/v1/auth/check-init
/// 检查系统是否已经初始化了管理员
pub async fn check_init(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_users")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or(0);

    Json(serde_json::json!({
        "need_init": count == 0
    }))
}

/// POST /api/v1/auth/init
/// 初始化管理员
pub async fn init_admin(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthPayload>,
) -> Json<serde_json::Value> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_users")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or(0);

    if count > 0 {
        return Json(serde_json::json!({
            "status": "error",
            "message": "系统已被初始化，拒绝再次创建超级管理员。"
        }));
    }

    if payload.username.is_empty() || payload.password.len() < 6 {
        return Json(serde_json::json!({
            "status": "error",
            "message": "用户名为空或密码太短（至少6位）"
        }));
    }

    let hashed_password = match hash(&payload.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return Json(serde_json::json!({ "status": "error", "message": "密码加密失败" })),
    };

    let res = sqlx::query!(
        "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
        payload.username,
        hashed_password
    )
    .execute(&state.db_pool)
    .await;

    match res {
        Ok(_) => Json(serde_json::json!({
            "status": "success",
            "message": "系统初始化成功，超级管理员创建完毕！"
        })),
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("数据库错误: {}", e)
        })),
    }
}

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthPayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user_record = sqlx::query!("SELECT id, password_hash FROM admin_users WHERE username = ?", payload.username)
        .fetch_optional(&state.db_pool)
        .await
        .unwrap_or(None);

    if let Some(user) = user_record {
        if verify(&payload.password, &user.password_hash).unwrap_or(false) {
            // Update last login
            let _ = sqlx::query!("UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", user.id)
                .execute(&state.db_pool)
                .await;

            let my_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_waf_key_please_change".to_string());
            let exp = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(24))
                .expect("valid timestamp")
                .timestamp() as usize;

            let claims = Claims {
                sub: payload.username.clone(),
                exp,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(my_secret.as_bytes()),
            )
            .unwrap();

            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "success",
                    "message": "登录成功",
                    "token": token
                })),
            );
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "status": "error",
            "message": "用户名或密码错误"
        })),
    )
}

/// 全局 Auth 拦截器
pub async fn auth_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path();
    
    // 放行所有非 /api/v1 路径（比如静态文件）
    if !path.starts_with("/api/v1/") {
        return Ok(next.run(req).await);
    }

    // 放行 auth 相关的接口
    if path.starts_with("/api/v1/auth/") {
        return Ok(next.run(req).await);
    }

    // 从 Header 提取 Bearer Token
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|val| val.to_str().ok())
        .and_then(|str| {
            if str.starts_with("Bearer ") {
                Some(str[7..].to_string())
            } else {
                None
            }
        });

    if let Some(t) = token {
        let my_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_waf_key_please_change".to_string());
        let validation = Validation::default();
        if decode::<Claims>(&t, &DecodingKey::from_secret(my_secret.as_bytes()), &validation).is_ok() {
            return Ok(next.run(req).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
