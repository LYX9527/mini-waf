use mini_waf::{api, config, proxy, state};
use sqlx::mysql::MySqlPoolOptions;
use state::{AppState, AttackLog, Route, RouteType};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    println!("=== 启动 Rust 企业级 WAF ===");

    // 1. 连接 MySQL 数据库
    let db_url = std::env::var("DATABASE_URL").expect("必须在 .env 文件中设置 DATABASE_URL");
    println!("⏳ 正在连接 MySQL 数据库...");

    let pool = MySqlPoolOptions::new()
        .max_connections(config::DB_MAX_CONNECTIONS)
        .connect(&db_url)
        .await?;
    println!("✅ 数据库连接成功！");

    // 2. 加载 WAF 防御规则
    let rule_records = sqlx::query!("SELECT keyword FROM rules WHERE status = 1")
        .fetch_all(&pool)
        .await?;
    let initial_rules: Vec<String> = rule_records.into_iter().map(|r| r.keyword).collect();
    println!("🛡️ 已从数据库成功加载 {} 条防御规则", initial_rules.len());

    // 3. 加载微服务路由表 (按前缀长度降序，最长前缀匹配优先)
    let route_records = sqlx::query!(
        "SELECT path_prefix, upstream, route_type, is_spa FROM routes WHERE status = 1"
    )
    .fetch_all(&pool)
    .await?;
    let mut initial_routes: Vec<Route> = route_records
        .into_iter()
        .map(|r| Route {
            path_prefix: r.path_prefix,
            upstream: r.upstream,
            route_type: match r.route_type.as_str() {
                "static" => RouteType::Static,
                _ => RouteType::Proxy,
            },
            is_spa: r.is_spa != 0,
        })
        .collect();
    initial_routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));

    let proxy_count = initial_routes
        .iter()
        .filter(|r| r.route_type == RouteType::Proxy)
        .count();
    let static_count = initial_routes.len() - proxy_count;
    println!(
        "🌐 已从数据库加载 {} 个路由 (代理: {}, 静态: {})",
        initial_routes.len(),
        proxy_count,
        static_count
    );

    // 4. 创建异步日志通道
    let (log_tx, mut log_rx) = mpsc::channel::<AttackLog>(1000);

    // 5. 初始化缓存
    let rate_limiter = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(config::RATE_LIMIT_WINDOW_SECS))
        .build();
    let penalty_box = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(config::PENALTY_TTL_SECS))
        .build();
    let captcha_answers = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(config::CAPTCHA_TTL_SECS))
        .build();
    let verified_tokens = moka::sync::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(config::TOKEN_TTL_SECS))
        .build();

    // 6. 构建全局状态
    let state = Arc::new(AppState {
        rules: RwLock::new(initial_rules),
        routes: RwLock::new(initial_routes),
        log_tx,
        db_pool: pool.clone(),
        rate_limiter,
        penalty_box,
        captcha_answers,
        verified_tokens,
    });

    // 7. 后台任务：异步日志落盘
    let log_pool = pool.clone();
    tokio::spawn(async move {
        println!("📝 异步日志落盘守护进程已启动...");
        while let Some(log) = log_rx.recv().await {
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

    // 8. 启动管理 API
    let state_for_api = state.clone();
    tokio::spawn(async move {
        api::start_admin_server(state_for_api).await;
    });

    // 9. 启动 WAF 代理 (主线程阻塞)
    proxy::start_proxy_server(state).await;

    Ok(())
}
