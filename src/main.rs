use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use sqlx::mysql::MySqlPoolOptions; // 引入配置项
use std::collections::HashMap;
mod api;
mod proxy;
mod state;

use state::{AppState, AttackLog};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    println!("=== 启动 Rust 企业级 WAF ===");

    // 1. 根据你提供的账号密码构造 MySQL 连接字符串
    let db_url = std::env::var("DATABASE_URL").expect("必须在 .env 文件中设置 DATABASE_URL");
    println!("⏳ 正在连接 MySQL 数据库...");

    // 2. 创建高并发数据库连接池 (最大连接数设为 20)
    let pool = MySqlPoolOptions::new()
        .max_connections(20)
        .connect(&db_url)
        .await?;
    println!("✅ 数据库连接成功！");

    // 3. 从数据库中加载 [状态为启用(1)] 的规则到内存
    // 这里使用了 sqlx 的强大特性：直接将查询结果映射为内部元组
    let rule_records = sqlx::query!("SELECT keyword FROM rules WHERE status = 1")
        .fetch_all(&pool)
        .await?;

    let mut initial_rules = Vec::new();
    for record in rule_records {
        initial_rules.push(record.keyword);
    }
    println!("🛡️ 已从数据库成功加载 {} 条防御规则", initial_rules.len());

    // ⭐ 修改：从数据库加载微服务路由表
    let route_records = sqlx::query!("SELECT path_prefix, upstream FROM routes WHERE status = 1")
        .fetch_all(&pool)
        .await?;

    let mut initial_routes = Vec::new();
    for record in route_records {
        initial_routes.push((record.path_prefix, record.upstream));
    }

    // ⚔️ 核心架构逻辑：按路径长度从大到小排序 (最长前缀匹配优先)
    // 这样当访问 /api/v2/user 时，会先匹配 "/api/v2" 而不是 "/api"
    initial_routes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    println!("🌐 已从数据库加载 {} 个微服务 API 路由", initial_routes.len());



    let (log_tx, mut log_rx) = mpsc::channel::<AttackLog>(1000);
    // ⭐ 初始化限流器：记录最近 10 秒内的数据
    let rate_limiter = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(10))
        .build();

    // ⭐ 初始化小黑屋：封禁时间为 1 小时 (3600 秒)
    let penalty_box = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(3600))
        .build();

    // ⭐ 新增：验证码答案缓存，5分钟不答题就失效
    let captcha_answers = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(300))
        .build();

    // ⭐ 新增：验证通过的白名单，免死金牌有效时长 1 小时
    // let verified_ips = moka::sync::Cache::builder()
    //     .time_to_live(std::time::Duration::from_secs(3600))
    //     .build();
    let verified_tokens = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(3600))
        .build();
    // 4. 初始化全局共享状态 (把 pool 也放进去)
    let state = Arc::new(AppState {
        rules: RwLock::new(initial_rules),
        routes: RwLock::new(initial_routes), // 注入新的路由表
        log_tx,
        db_pool: pool.clone(),
        rate_limiter,
        penalty_box,
        captcha_answers, // 注入
        verified_tokens,    // 注入
    });

    // 5. 【后台任务】：异步日志入库 Worker
    let log_pool = pool.clone(); // 给日志线程克隆一份连接池
    tokio::spawn(async move {
        println!("📝 异步日志落盘守护进程已启动...");
        while let Some(log) = log_rx.recv().await {
            // 将拦截日志异步写入 MySQL
            let insert_result = sqlx::query!(
                "INSERT INTO attack_logs (ip_address, request_path, matched_rule) VALUES (?, ?, ?)",
                log.ip.to_string(),
                log.path,
                log.matched_rule
            )
                .execute(&log_pool)
                .await;

            match insert_result {
                Ok(_) => println!("💾 拦截日志已落盘 -> IP: {}", log.ip),
                Err(e) => eprintln!("❌ 日志入库失败: {}", e),
            }
        }
    });

    let state_for_api = state.clone();
    tokio::spawn(async move {
        api::start_admin_server(state_for_api).await;
    });

    let state_for_proxy = state.clone();
    proxy::start_proxy_server(state_for_proxy).await;

    Ok(())
}