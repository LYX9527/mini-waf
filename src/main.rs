use mini_waf::{api, config, proxy, state};
use sqlx::mysql::MySqlPoolOptions;
use state::{AccessLog, AppState, AttackLog, RealtimeCounters, Route, RouteType};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use mini_waf::{log_daemon, log_error, log_info, log_success, log_warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    log_info!("SYSTEM", "启动 MINI WAF");

    // 1. 连接 MySQL 数据库
    let db_url = std::env::var("DATABASE_URL").expect("必须在 .env 文件中设置 DATABASE_URL");
    log_info!("DATABASE", "正在连接 MySQL 数据库...");

    let pool = MySqlPoolOptions::new()
        .max_connections(config::DB_MAX_CONNECTIONS)
        .connect(&db_url)
        .await?;
    log_success!("DATABASE", "数据库连接成功！");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;
    log_success!("DATABASE", "数据库迁移完成");
    // 2. 加载 WAF 防御规则
    let rule_records = sqlx::query!("SELECT keyword, target_field, match_type FROM rules WHERE status = 1")
        .fetch_all(&pool)
        .await?;
    let initial_rules: Vec<state::WafRule> = rule_records.into_iter().map(|r| {
        let compiled_regex = if r.match_type == "Regex" {
            regex::Regex::new(&r.keyword).ok()
        } else {
            None
        };
        state::WafRule {
            keyword: r.keyword,
            target_field: r.target_field,
            match_type: r.match_type,
            compiled_regex,
        }
    }).collect();
    log_success!("RULE_ENG", "已从数据库成功加载 {} 条防御规则", initial_rules.len());

    // 3. 加载微服务路由表 (按前缀长度降序，最长前缀匹配优先)
    // 排序规则：有 host_pattern 的路由排在前面（优先级更高），然后按路径长度降序
    let route_records = sqlx::query!(
        "SELECT path_prefix, host_pattern, upstream, route_type FROM routes WHERE status = 1"
    )
    .fetch_all(&pool)
    .await?;
    let mut initial_routes: Vec<Route> = route_records
        .into_iter()
        .map(|r| Route {
            path_prefix: r.path_prefix,
            host_pattern: r.host_pattern,
            upstream: r.upstream,
            route_type: RouteType::Proxy,
            rr_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
        .collect();
    // 有 host_pattern 的路由优先级 > 路径更长的路由 > 通配路由
    initial_routes.sort_by(|a, b| {
        match (a.host_pattern.is_some(), b.host_pattern.is_some()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => b.path_prefix.len().cmp(&a.path_prefix.len()),
        }
    });

    log_success!("ROUTER", "已从数据库加载 {} 个路由", initial_routes.len());

    // 4. 加载 IP 黑白名单到内存
    let blacklist_records = sqlx::query!("SELECT ip_address FROM ip_blacklist")
        .fetch_all(&pool)
        .await?;
    let initial_blacklist: HashSet<String> = blacklist_records
        .into_iter()
        .map(|r| r.ip_address)
        .collect();
    log_success!("FIREWALL", "已加载 {} 条 IP 黑名单", initial_blacklist.len());

    let whitelist_records = sqlx::query!("SELECT ip_address FROM ip_whitelist")
        .fetch_all(&pool)
        .await?;
    let initial_whitelist: HashSet<String> = whitelist_records
        .into_iter()
        .map(|r| r.ip_address)
        .collect();
    log_success!("FIREWALL", "已加载 {} 条 IP 白名单", initial_whitelist.len());

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

    // 8. 获取全局设置
    let block_page_row = sqlx::query!("SELECT setting_value FROM system_settings WHERE setting_key = 'custom_block_page'")
        .fetch_optional(&pool)
        .await?;
    let custom_block_page = block_page_row.map(|r| r.setting_value).unwrap_or_default();

    let geo_countries_row = sqlx::query!("SELECT setting_value FROM system_settings WHERE setting_key = 'geo_blocked_countries'")
        .fetch_optional(&pool)
        .await?;
    let geo_str = geo_countries_row.map(|r| r.setting_value).unwrap_or_default();
    let initial_geo_blocked: HashSet<String> = geo_str.split(',').filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_uppercase()).collect();

    let mut geo_db = None;
    if let Ok(mmdb_path) = std::env::var("MMDB_PATH") {
        if !mmdb_path.is_empty() {
            match maxminddb::Reader::open_readfile(&mmdb_path) {
                Ok(reader) => {
                    log_success!("GEO_BLOCK", "成功加载全球 IP 库: {}", mmdb_path);
                    geo_db = Some(reader);
                }
                Err(e) => log_error!("GEO_BLOCK", "无法加载 IP 库 {}: {}", mmdb_path, e),
            }
        }
    } else {
         log_warn!("GEO_BLOCK", "未配置 MMDB_PATH 环境变量，Geo-Blocking 功能将处于静默状态。");
    }

    // 9. 构建全局状态
    let state = Arc::new(AppState {
        rules: RwLock::new(initial_rules),
        routes: RwLock::new(initial_routes),
        log_tx,
        db_pool: pool.clone(),
        custom_block_page: RwLock::new(custom_block_page),
        rate_limiter,
        penalty_box,
        captcha_answers,
        verified_tokens,
        ip_blacklist: RwLock::new(initial_blacklist),
        ip_whitelist: RwLock::new(initial_whitelist),
        access_log_tx,
        counters: RealtimeCounters::new(),
        geo_db,
        geo_blocked_countries: RwLock::new(initial_geo_blocked),
        healthy_upstreams: RwLock::new(HashSet::new()),
    });

    // 10. 后台任务：攻击日志落盘
    let log_pool = pool.clone();
    tokio::spawn(async move {
        log_daemon!("DAEMON", "攻击日志落盘守护进程已启动...");
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
                Ok(_) => log_success!("DAEMON_LOG", "拦截日志已落盘 -> IP: {}", log.ip),
                Err(e) => log_error!("DAEMON_LOG", "拦截日志入库失败: {}", e),
            }
        }
    });

    // 10. 后台任务：访问日志批量落盘
    let access_pool = pool.clone();
    tokio::spawn(async move {
        log_daemon!("DAEMON", "访问日志批量落盘守护进程已启动...");
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
                "INSERT INTO access_logs (ip_address, request_path, method, status_code, is_blocked, matched_rule, user_agent, referer, country, city) VALUES ",
            );
            let values: Vec<String> = batch
                .iter()
                .map(|l| {
                    format!(
                        "('{}', '{}', '{}', {}, {}, {}, '{}', '{}', {}, {})",
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
                        l.referer.replace('\'', "''").chars().take(2048).collect::<String>(),
                        l.country.as_ref().map(|c| format!("'{}'", c.replace('\'', "''"))).unwrap_or_else(|| "NULL".to_string()),
                        l.city.as_ref().map(|c| format!("'{}'", c.replace('\'', "''"))).unwrap_or_else(|| "NULL".to_string()),
                    )
                })
                .collect();
            query.push_str(&values.join(","));

            if let Err(e) = sqlx::query(&query).execute(&access_pool).await {
                log_error!("DAEMON_LOG", "访问日志批量入库失败: {}", e);
            }
            batch.clear();
        }
    });

    // 11. 启动管理 API
    let state_for_api = state.clone();
    tokio::spawn(async move {
        api::start_admin_server(state_for_api).await;
    });

    // 11.5 启动负载均衡健康侦测协程
    let state_for_health = state.clone();
    tokio::spawn(async move {
        proxy::health::start_health_checker(state_for_health).await;
    });

    // 12.0 启动 TLS HTTPS 代理 (如果配置了证书)
    if let (Ok(cert), Ok(key)) = (std::env::var("TLS_CERT_PATH"), std::env::var("TLS_KEY_PATH")) {
        if !cert.is_empty() && !key.is_empty() {
            let port = std::env::var("TLS_PORT").unwrap_or_else(|_| "443".to_string()).parse::<u16>().unwrap_or(443);
            let state_for_tls = state.clone();
            tokio::spawn(async move {
                proxy::tls::start_tls_proxy_server(state_for_tls, &cert, &key, port).await;
            });
        }
    }

    // 12. 启动 WAF HTTP 代理 (主线程阻塞)
    proxy::start_proxy_server(state).await;

    Ok(())
}
