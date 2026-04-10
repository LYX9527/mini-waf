use std::net::SocketAddr;
use tokio::sync::{mpsc, RwLock};
use sqlx::MySqlPool; // 引入 MySqlPool
use moka::sync::Cache; // 引入 Moka 缓存
// 攻击日志结构体
#[derive(Debug)]
pub struct AttackLog {
    pub time: String,
    pub ip: SocketAddr,
    pub path: String,
    pub matched_rule: String,
}
#[derive(Clone, Debug)]
pub struct ClientFingerprint {
    pub ip: String,
    pub user_agent: String,
    // 未来你还可以加入更多特征，比如 Accept-Language, TLS JA3 指纹等
}

// 整个 WAF 的全局状态
pub struct AppState {
    pub rules: RwLock<Vec<String>>,
    pub routes: RwLock<Vec<(String, String)>>,
    pub log_tx: mpsc::Sender<AttackLog>,
    pub db_pool: MySqlPool,
    pub rate_limiter: Cache<String, u32>,
    pub penalty_box: Cache<String, u32>,
    pub captcha_answers: Cache<String, (u32, u32)>,
    // pub verified_ips: Cache<String, bool>,
    pub verified_tokens: Cache<String, ClientFingerprint>,
}