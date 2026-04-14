use moka::sync::Cache;
use sqlx::MySqlPool;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
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

/// 路由类型：反向代理 或 静态文件
#[derive(Clone, Debug, PartialEq)]
pub enum RouteType {
    Proxy,
    Static,
}

/// 路由条目
#[derive(Clone, Debug)]
pub struct Route {
    pub path_prefix: String,
    pub upstream: String, // proxy: host:port, static: 文件系统目录路径
    pub route_type: RouteType,
    pub is_spa: bool, // 仅对 static 有意义
}

/// 访问日志（所有请求）
#[derive(Debug)]
pub struct AccessLog {
    pub ip: String,
    pub path: String,
    pub method: String,
    pub status_code: u16,
    pub is_blocked: bool,
    pub matched_rule: Option<String>,
    pub user_agent: String,
    pub referer: String,
}

/// 实时计数器（原子操作，无锁）
pub struct RealtimeCounters {
    pub total_requests_today: AtomicU64,
    pub blocked_requests_today: AtomicU64,
    pub start_time: Instant,
    /// QPS 滑动窗口：记录最近 10 秒内每个请求的时间戳和累计计数
    pub qps_window: RwLock<VecDeque<(Instant, u64)>>,
}

impl RealtimeCounters {
    pub fn new() -> Self {
        Self {
            total_requests_today: AtomicU64::new(0),
            blocked_requests_today: AtomicU64::new(0),
            start_time: Instant::now(),
            qps_window: RwLock::new(VecDeque::with_capacity(10000)),
        }
    }
}

/// WAF 全局共享状态
pub struct AppState {
    pub rules: RwLock<Vec<String>>,
    pub routes: RwLock<Vec<Route>>,
    pub log_tx: mpsc::Sender<AttackLog>,
    pub db_pool: MySqlPool,
    pub rate_limiter: Cache<String, u32>,
    pub penalty_box: Cache<String, u32>,
    pub captcha_answers: Cache<String, (u32, u32)>,
    pub verified_tokens: Cache<String, ClientFingerprint>,
    // 黑白名单（内存 HashSet，O(1) 查找）
    pub ip_blacklist: RwLock<HashSet<String>>,
    pub ip_whitelist: RwLock<HashSet<String>>,
    // 访问日志通道
    pub access_log_tx: mpsc::Sender<AccessLog>,
    // 实时计数器
    pub counters: RealtimeCounters,
}
