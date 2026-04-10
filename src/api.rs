use crate::state::AppState;
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

// 定义接收客户端 POST 请求的 JSON 结构
#[derive(Deserialize)]
pub struct AddRuleRequest {
    pub rule: String,
}

// 定义返回给客户端的 JSON 结构
#[derive(Serialize)]
pub struct RulesResponse {
    pub rules: Vec<String>,
}

// GET /rules：获取当前所有拦截规则
async fn get_rules(State(state): State<Arc<AppState>>) -> Json<RulesResponse> {
    // 获取读锁
    let rules = state.rules.read().await;
    Json(RulesResponse {
        rules: rules.clone(),
    })
}

// POST /rules：动态添加一条新规则
// POST /rules：动态添加一条新规则，并持久化到数据库
async fn add_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddRuleRequest>,
) -> Json<serde_json::Value> {

    // 1. 先写入 MySQL 数据库
    let insert_result = sqlx::query!(
        "INSERT INTO rules (keyword, rule_type, status) VALUES (?, 'CUSTOM', 1)",
        payload.rule
    )
        .execute(&state.db_pool)
        .await;

    match insert_result {
        Ok(_) => {
            // 2. 数据库写入成功后，再更新内存中的读写锁，实现热生效
            let mut rules = state.rules.write().await;
            if !rules.contains(&payload.rule) {
                rules.push(payload.rule.clone());
            }

            Json(serde_json::json!({
                "status": "success",
                "message": format!("WAF 规则 '{}' 已持久化并动态生效！", payload.rule)
            }))
        }
        Err(e) => {
            // 如果遇到唯一键冲突等错误
            Json(serde_json::json!({
                "status": "error",
                "message": format!("规则添加失败: {}", e)
            }))
        }
    }
}

// 启动管理 API 服务
pub async fn start_admin_server(state: Arc<AppState>) {
    let app = Router::new()
        .route("/rules", get(get_rules))
        .route("/rules", post(add_rule))
        .with_state(state); // 将全局状态注入到 API 中

    let listener = TcpListener::bind("127.0.0.1:8081").await.unwrap();
    println!("⚙️ 管理控制台 API 启动成功，监听 http://127.0.0.1:8081");

    // 启动 axum 服务
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("管理 API 运行异常: {}", e);
    }
}