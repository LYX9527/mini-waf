use mini_waf::{api, config, proxy, state};
use sqlx::mysql::MySqlPoolOptions;
use state::{AccessLog, AppState, AttackLog, RealtimeCounters, Route, RouteType};
use std::collections::HashSet;
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

    // 4. 加载 IP 黑白名单到内存
    let blacklist_records = sqlx::query!("SELECT ip_address FROM ip_blacklist")
        .fetch_all(&pool)
        .await?;
    let initial_blacklist: HashSet<String> = blacklist_records
        .into_iter()
        .map(|r| r.ip_address)
        .collect();
    println!("🚫 已加载 {} 条 IP 黑名单", initial_blacklist.len());

    let whitelist_records = sqlx::query!("SELECT ip_address FROM ip_whitelist")
        .fetch_all(&pool)
        .await?;
    let initial_whitelist: HashSet<String> = whitelist_records
        .into_iter()
        .map(|r| r.ip_address)
        .collect();
    println!("✅ 已加载 {} 条 IP 白名单", initial_whitelist.len());

    // 5. 创建异步日志通道
    let (log_tx, mut log_rx) = mpsc::channel::<AttackLog>(1000);

    // 6. 创建访问日志通道
    let (access_log_tx, mut access_log_rx) = mpsc::channel::<AccessLog>(5000);

    // 7. 初始化缓存
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

    // 8. 构建全局状态
    let state = Arc::new(AppState {
        rules: RwLock::new(initial_rules),
        routes: RwLock::new(initial_routes),
        log_tx,
        db_pool: pool.clone(),
        rate_limiter,
        penalty_box,
        captcha_answers,
        verified_tokens,
        ip_blacklist: RwLock::new(initial_blacklist),
        ip_whitelist: RwLock::new(initial_whitelist),
        access_log_tx,
        counters: RealtimeCounters::new(),
    });

    // 9. 后台任务：攻击日志落盘
    let log_pool = pool.clone();
    tokio::spawn(async move {
        println!("📝 攻击日志落盘守护进程已启动...");
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

    // 10. 后台任务：访问日志批量落盘
    let access_pool = pool.clone();
    tokio::spawn(async move {
        println!("📊 访问日志批量落盘守护进程已启动...");
        let mut batch: Vec<AccessLog> = Vec::with_capacity(config::ACCESS_LOG_BATCH_SIZE);
        loop {
            let timeout = tokio::time::sleep(std::time::Duration::from_millis(
                config::ACCESS_LOG_BATCH_INTERVAL_MS,
            ));
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    log_opt = access_log_rx.recv() => {
                        match log_opt {
                            Some(log) => {
                                batch.push(log);
                                if batch.len() >= config::ACCESS_LOG_BATCH_SIZE {
                                    break;
                                }
                            }
                            None => return, // channel 关闭
                        }
                    }
                    _ = &mut timeout => {
                        if !batch.is_empty() {
                            break;
                        }
                    }
                }
            }

            if batch.is_empty() {
                continue;
            }

            // 批量 INSERT
            let mut query = String::from(
                "INSERT INTO access_logs (ip_address, request_path, method, status_code, is_blocked, matched_rule, user_agent) VALUES ",
            );
            let values: Vec<String> = batch
                .iter()
                .map(|l| {
                    format!(
                        "('{}', '{}', '{}', {}, {}, {}, '{}')",
                        l.ip.replace('\'', "''"),
                        l.path.replace('\'', "''").chars().take(2048).collect::<String>(),
                        l.method,
                        l.status_code,
                        if l.is_blocked { 1 } else { 0 },
                        l.matched_rule
                            .as_ref()
                            .map(|r| format!("'{}'", r.replace('\'', "''")))
                            .unwrap_or_else(|| "NULL".to_string()),
                        l.user_agent.replace('\'', "''").chars().take(1024).collect::<String>(),
                    )
                })
                .collect();
            query.push_str(&values.join(","));

            if let Err(e) = sqlx::query(&query).execute(&access_pool).await {
                eprintln!("❌ 访问日志批量入库失败: {}", e);
            }
            batch.clear();
        }
    });

    // 11. 启动管理 API
    let state_for_api = state.clone();
    tokio::spawn(async move {
        api::start_admin_server(state_for_api).await;
    });

    // 12. 启动 WAF 代理 (主线程阻塞)
    proxy::start_proxy_server(state).await;

    Ok(())
}
