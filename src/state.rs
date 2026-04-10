use moka::sync::Cache;
use sqlx::MySqlPool;
use std::net::SocketAddr;
use tokio::sync::{mpsc, RwLock};

/// 攻击日志结构体
#[derive(Debug)]
pub struct AttackLog {
    pub time: String,
    pub ip: SocketAddr,
    pub path: String,
    pub matched_rule: String,
}

/// 客户端环境指纹 —— 用于绑定通行令牌
#[derive(Clone, Debug)]
pub struct ClientFingerprint {
    pub ip: String,
    pub user_agent: String,
}

/// WAF 全局共享状态
pub struct AppState {
    pub rules: RwLock<Vec<String>>,
    pub routes: RwLock<Vec<(String, String)>>,
    pub log_tx: mpsc::Sender<AttackLog>,
    pub db_pool: MySqlPool,
    pub rate_limiter: Cache<String, u32>,
    pub penalty_box: Cache<String, u32>,
    pub captcha_answers: Cache<String, (u32, u32)>,
    pub verified_tokens: Cache<String, ClientFingerprint>,
}
