use moka::sync::Cache;
use regex::Regex;
use sqlx::MySqlPool;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

#[derive(Clone, Debug)]
pub struct SystemSettings {
    pub rate_limit_threshold: u64,
    pub penalty_ban_score: u32,
    pub penalty_attack_score: u32,
    pub token_ttl_secs: u64,
    pub captcha_ttl_secs: u64,
    pub rate_limit_window_secs: u64,
    pub penalty_ttl_secs: u64,
    pub trust_upstream_proxy: bool,
}

impl Default for SystemSettings {
    fn default() -> Self {
        Self {
            rate_limit_threshold: crate::config::RATE_LIMIT_THRESHOLD as u64,
            penalty_ban_score: crate::config::PENALTY_BAN_SCORE,
            penalty_attack_score: crate::config::PENALTY_ATTACK_SCORE,
            token_ttl_secs: crate::config::TOKEN_TTL_SECS,
            captcha_ttl_secs: crate::config::CAPTCHA_TTL_SECS,
            rate_limit_window_secs: crate::config::RATE_LIMIT_WINDOW_SECS,
            penalty_ttl_secs: crate::config::PENALTY_TTL_SECS,
            trust_upstream_proxy: false,
        }
    }
}

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

/// WAF 规则对象
#[derive(Clone, Debug)]
pub struct WafRule {
    pub keyword: String,
    pub target_field: String, // "URL", "Header", "Body", "User-Agent"
    pub match_type: String,   // "Contains", "Regex", "Exact"
    pub rule_type: String,    // "DEFAULT", "CUSTOM"
    pub compiled_regex: Option<Regex>,
}

/// 路由类型
#[derive(Clone, Debug, PartialEq)]
pub enum RouteType {
    Proxy,
}

/// 路由条目
#[derive(Clone, Debug)]
pub struct Route {
    pub path_prefix: String,
    /// 域名匹配模式，None 表示匹配所有域名，支持通配符 *.example.com
    pub host_pattern: Option<String>,
    pub upstream: String, // host:port
    pub route_type: RouteType,
    pub rr_counter: Arc<AtomicUsize>,
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
    pub country: Option<String>,
    pub city: Option<String>,
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
    pub rules: RwLock<Vec<WafRule>>,
    pub routes: RwLock<Vec<Route>>,
    pub log_tx: mpsc::Sender<AttackLog>,
    pub db_pool: MySqlPool,
    pub custom_block_page: RwLock<String>,
    pub rate_limiter: RwLock<Cache<String, u64>>,
    pub penalty_box: RwLock<Cache<String, u32>>,
    pub captcha_answers: RwLock<Cache<String, (u32, u32)>>,
    pub verified_tokens: RwLock<Cache<String, ClientFingerprint>>,
    // 黑白名单（内存 HashSet，O(1) 查找）
    pub ip_blacklist: RwLock<HashSet<String>>,
    pub ip_whitelist: RwLock<HashSet<String>>,
    // 访问日志通道
    pub access_log_tx: mpsc::Sender<AccessLog>,
    // 实时计数器
    pub counters: RealtimeCounters,
    
    // Geo-Blocking & Load Balancing
    pub geo_db: Option<maxminddb::Reader<Vec<u8>>>,
    pub geo_blocked_countries: RwLock<HashSet<String>>,
    pub healthy_upstreams: RwLock<HashSet<String>>,
    
    // 动态全局设置
    pub settings: RwLock<SystemSettings>,
    
    // 动态 SNI 证书挂载中心
    pub cert_resolver: Arc<crate::proxy::tls::DynamicCertResolver>,
}
