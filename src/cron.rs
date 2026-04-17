use crate::state::AppState;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub async fn start_acme_renew_daemon(state: Arc<AppState>) {
    crate::log_daemon!("ACME_CRON", "自动化证书续签守护进程已启动 (每 12 小时检查一次)");
    loop {
        // 每 12 小时检查一次
        sleep(Duration::from_secs(12 * 3600)).await;

        crate::log_info!("ACME_CRON", "开始执行自动续签检查...");
        
        // 1. 查出需要自动续签的域名
        let rows = sqlx::query!("SELECT domain, cert_path, key_path FROM ssl_certs WHERE auto_renew = 1")
            .fetch_all(&state.db_pool)
            .await
            .unwrap_or_default();
            
        let mut renewed_count = 0;
            
        for row in rows {
            // 解析剩余时间
            let needs_renew = {
                let mut expired = true;
                if let Ok(pem_data) = std::fs::read(&row.cert_path) {
                    if let Ok((_, pem)) = x509_parser::prelude::parse_x509_pem(&pem_data) {
                        if let Ok((_, cert)) = x509_parser::prelude::parse_x509_certificate(&pem.contents) {
                            let not_after = cert.validity().not_after.timestamp();
                            let now = chrono::Utc::now().timestamp();
                            // 如果距离过期不足 20 天，执行续签
                            if not_after - now < 20 * 86400 {
                                expired = true;
                            } else {
                                expired = false;
                            }
                        }
                    }
                }
                expired
            };

            if !needs_renew {
                continue;
            }

            crate::log_info!("ACME_CRON", "准备续签域名: {}", row.domain);
            
            // 2. 调起 certbot renew (因为 certbot 本地其实有 /etc/letsencrypt/renewal/ 配置)
            // 我们可以直接执行 certbot renew --cert-name domain --quiet
            let cert_name = row.domain.trim_start_matches("*.");
            let output = crate::api::nginx::docker_exec_in(
                "mini-waf-certbot",
                vec![
                    "certbot",
                    "renew",
                    "--cert-name",
                    cert_name,
                    "--quiet",
                ],
            ).await;

            if let Ok(out_bytes) = output {
                let out = String::from_utf8_lossy(&out_bytes).into_owned();
                if out.contains("successfully") || out.contains("not yet due") || out.is_empty() {
                    renewed_count += 1;
                    
                    // 3. 解析最新时间并更新数据库
                    if let Ok(pem_data) = std::fs::read(&row.cert_path) {
                        if let Ok((_, pem)) = x509_parser::prelude::parse_x509_pem(&pem_data) {
                            if let Ok((_, cert)) = x509_parser::prelude::parse_x509_certificate(&pem.contents) {
                                let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();
                                let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
                                let issuer = cert.issuer().to_string();

                                let format = "%a, %d %b %Y %H:%M:%S %z";
                                let na_dt = chrono::DateTime::parse_from_str(&not_after, format).ok().map(|d| d.naive_utc());
                                let nb_dt = chrono::DateTime::parse_from_str(&not_before, format).ok().map(|d| d.naive_utc());

                                let _ = sqlx::query!(
                                    "UPDATE ssl_certs SET not_before=?, not_after=?, issuer=?, updated_at=NOW() WHERE domain=?",
                                    nb_dt, na_dt, issuer, row.domain
                                ).execute(&state.db_pool).await;

                                // 4. 热重载到 SNI 挂载中心
                                if let Err(e) = state.cert_resolver.add_cert(&row.domain, &row.cert_path, &row.key_path) {
                                    crate::log_error!("ACME_CRON", "续签域名 {} 热重载 SNI 失败: {}", row.domain, e);
                                } else {
                                    crate::log_success!("ACME_CRON", "续签域名 {} 成功并热重载 SNI", row.domain);
                                }
                            }
                        }
                    }
                } else {
                    crate::log_error!("ACME_CRON", "续签域名 {} 失败: {}", row.domain, out);
                }
            }
        }
        
        crate::log_info!("ACME_CRON", "自动化续签检查完成，本次成功续签 {} 个域。", renewed_count);
    }
}
