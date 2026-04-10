/// 全局配置常量 —— 所有魔法数字集中管理

// 网络监听地址
pub const PROXY_ADDR: ([u8; 4], u16) = ([0, 0, 0, 0], 48080);
pub const ADMIN_ADDR: &str = "127.0.0.1:8081";

// 数据库连接池
pub const DB_MAX_CONNECTIONS: u32 = 20;

// 限流配置
pub const RATE_LIMIT_WINDOW_SECS: u64 = 10;
pub const RATE_LIMIT_THRESHOLD: u32 = 20;

// 惩罚机制
pub const PENALTY_TTL_SECS: u64 = 3600; // 1 小时
pub const PENALTY_BAN_SCORE: u32 = 100; // 累积到此分数封禁
pub const PENALTY_ATTACK_SCORE: u32 = 50; // 每次攻击增加的分数

// 验证码
pub const CAPTCHA_TTL_SECS: u64 = 300; // 5 分钟

// 通行令牌
pub const TOKEN_TTL_SECS: u64 = 3600; // 1 小时

// JS 质询延迟 (Tarpit)
pub const JS_CHALLENGE_DELAY_MS: u64 = 2500;
