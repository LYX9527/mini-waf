/// SSL 证书管理 API
/// 证书存储路径: /certs/{domain}/fullchain.pem + privkey.pem
/// nginx 容器挂载同一卷，路径: /etc/nginx/certs/{domain}/
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

use crate::state::AppState;

// 证书根目录（WAF 容器内，读写权限）
const CERTS_ROOT: &str = "/certs";
// nginx 容器内挂载路径（用于生成 nginx 配置）
const NGINX_CERTS_ROOT: &str = "/etc/nginx/certs";
// certbot 容器内，同一个 nginx_certs 卷挂载于 /etc/letsencrypt
// WAF  -> /certs/<path>  ==  certbot -> /etc/letsencrypt/<path>
const CERTBOT_CERTS_ROOT: &str = "/etc/letsencrypt";
// 凭证 ini 文件在 WAF 容器内的写入目录
const CERTS_TMP_HOST: &str = "/certs/tmp";
// 同一写入目录在 certbot 容器内的读取路径
const CERTS_TMP_CERTBOT: &str = "/etc/letsencrypt/tmp";

// ─── 域名安全校验 ──────────────────────────────────────────────────────────────
fn validate_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // 只允许字母、数字、点、连字符、通配符 *（仅头部）
    domain.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'))
        && !domain.contains("..")
        && !domain.contains('/')
        && !domain.contains('\\')
}

// ─── 证书目录路径 ──────────────────────────────────────────────────────────────
fn cert_dir(domain: &str) -> PathBuf {
    PathBuf::from(CERTS_ROOT).join(domain)
}

// ─── X.509 证书解析：读取 not_after / issuer ──────────────────────────────────
#[derive(Serialize, Clone)]
pub struct CertInfo {
    pub domain: String,
    pub issuer: String,
    pub not_after: String,   // ISO8601
    pub not_before: String,
    pub days_remaining: i64,
    pub status: String,      // "valid" | "expiring" | "expired"
    pub auto_renew: bool,
    pub acme_method: String,
}

fn parse_cert_file(pem_path: &std::path::Path) -> Option<(String, String, String)> {
    use x509_parser::prelude::*;
    let pem_data = std::fs::read(pem_path).ok()?;
    let (_, pem) = parse_x509_pem(&pem_data).ok()?;
    let (_, cert) = parse_x509_certificate(&pem.contents).ok()?;

    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();
    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();

    let issuer = cert.issuer().to_string();

    Some((issuer, not_before, not_after))
}

fn days_until_expiry(not_after: &str) -> i64 {
    use chrono::{DateTime, Utc};
    if let Ok(dt) = DateTime::parse_from_rfc2822(not_after) {
        let now = Utc::now();
        (dt.with_timezone(&Utc) - now).num_days()
    } else {
        // 无法解析日期时返回 0（而非 999），避免显示虚假的剩余天数
        0
    }
}

/// 直接从 数据库取出的 NaiveDateTime 计算剩余天数
fn days_from_naive(dt: Option<chrono::NaiveDateTime>) -> i64 {
    use chrono::Utc;
    match dt {
        Some(naive) => {
            let utc_dt = chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
            (utc_dt - Utc::now()).num_days()
        }
        None => 0,
    }
}

// ─── GET /ssl/certs ────────────────────────────────────────────────────────────
pub async fn list_certs(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT domain, cert_path, not_after, not_before, issuer, auto_renew, acme_method FROM ssl_certs ORDER BY not_after ASC"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let mut certs: Vec<serde_json::Value> = Vec::new();
    for row in &rows {
        use sqlx::Row;
        let domain: String = row.get("domain");
        let cert_path: String = row.get("cert_path");
        let not_after: Option<chrono::NaiveDateTime> = row.get("not_after");
        let not_before: Option<chrono::NaiveDateTime> = row.get("not_before");
        let issuer: Option<String> = row.get("issuer");
        let auto_renew: bool = row.get::<i8, _>("auto_renew") != 0;
        let acme_method: Option<String> = row.get("acme_method");

        // 优先从文件解析（更准确），文件不可读时回退到 DB 数据
        let cert_path_obj = std::path::Path::new(&cert_path);
        let (live_issuer, live_na, days) = if let Some((fi, _, fna)) = parse_cert_file(cert_path_obj) {
            let d = days_until_expiry(&fna);
            (fi, fna, d)
        } else {
            // 文件不可读：直接用 DB 的 NaiveDateTime 计算，不经过 RFC2822 转换
            let iss = issuer.clone().unwrap_or_else(|| "Let's Encrypt".to_string());
            let na_str = not_after.map(|d| d.to_string()).unwrap_or_default();
            let d = days_from_naive(not_after);
            (iss, na_str, d)
        };

        let status = if days < 0 {
            "expired"
        } else if days <= 15 {
            "expiring"
        } else {
            "valid"
        };

        certs.push(serde_json::json!({
            "domain": domain,
            "issuer": live_issuer,
            "not_before": not_before.map(|d| d.to_string()).unwrap_or_default(),
            "not_after": live_na,
            "days_remaining": days,
            "status": status,
            "auto_renew": auto_renew,
            "acme_method": acme_method.unwrap_or_else(|| "http01".to_string()),
        }));
    }

    Json(serde_json::json!({ "certs": certs }))
}

// ─── GET /ssl/domains ─────────────────────────────────────────────────────────
/// 仅返回已安装证书的域名列表（供站点管理下拉使用）
pub async fn list_cert_domains(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = sqlx::query("SELECT domain FROM ssl_certs ORDER BY domain")
        .fetch_all(&state.db_pool)
        .await
        .unwrap_or_default();
    let domains: Vec<String> = rows.iter().map(|r| {
        use sqlx::Row;
        r.get("domain")
    }).collect();
    Json(serde_json::json!({ "domains": domains }))
}

// ─── POST /ssl/certs/upload ───────────────────────────────────────────────────
/// multipart 上传: field "domain" + "cert" (fullchain.pem) + "key" (privkey.pem)
pub async fn upload_cert(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut domain = String::new();
    let mut cert_bytes: Option<Vec<u8>> = None;
    let mut key_bytes: Option<Vec<u8>>  = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        let data = match field.bytes().await {
            Ok(b) => b.to_vec(),
            Err(_) => continue,
        };
        if data.len() > 1024 * 1024 {
            return (StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "status": "error", "message": "文件过大（限 1MB）" }))
            ).into_response();
        }
        match name.as_str() {
            "domain" => domain = String::from_utf8_lossy(&data).trim().to_string(),
            "cert"   => cert_bytes = Some(data),
            "key"    => key_bytes  = Some(data),
            _ => {}
        }
    }

    // 1. 校验域名
    if !validate_domain(&domain) {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": "无效的域名格式" }))
        ).into_response();
    }

    // 2. 校验文件
    let cert_data = match cert_bytes {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": "缺少证书文件" }))
        ).into_response(),
    };
    let key_data = match key_bytes {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": "缺少私钥文件" }))
        ).into_response(),
    };

    // 3. 验证 PEM 格式
    let cert_ok = {
        let mut rdr = std::io::BufReader::new(cert_data.as_slice());
        rustls_pemfile::certs(&mut rdr)
            .collect::<Result<Vec<_>, _>>()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    };
    if !cert_ok {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": "证书文件格式错误或不含有效 PEM 证书" }))
        ).into_response();
    }

    let key_valid = {
        let mut rdr = std::io::BufReader::new(key_data.as_slice());
        rustls_pemfile::private_key(&mut rdr).unwrap_or(None).is_some()
    };
    if !key_valid {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": "私钥文件格式错误或未包含有效私钥" }))
        ).into_response();
    }

    // 4. 解析证书元数据（从第一张 DER 重建 PEM 临时文件解析）
    let (issuer, not_before_str, not_after_str) = {
        let mut tmp_rdr = std::io::BufReader::new(cert_data.as_slice());
        let first_der = rustls_pemfile::certs(&mut tmp_rdr)
            .filter_map(|r| r.ok()).next().map(|d| d.to_vec());
        if let Some(der_bytes) = first_der {
            let pem_str = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                base64_encode_cert(&der_bytes)
            );
            let tmp_path = std::env::temp_dir().join(format!("waf_cert_{}.pem", &domain));
            let _ = std::fs::write(&tmp_path, pem_str.as_bytes());
            let result = parse_cert_file(&tmp_path);
            let _ = std::fs::remove_file(&tmp_path);
            result.unwrap_or_else(|| ("Unknown CA".to_string(), "".to_string(), "".to_string()))
        } else {
            ("Unknown CA".to_string(), "".to_string(), "".to_string())
        }
    };

    // 5. 写文件（私钥 600 权限）
    let dir = cert_dir(&domain);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "error", "message": format!("创建证书目录失败: {}", e) }))
        ).into_response();
    }
    let cert_path = dir.join("fullchain.pem");
    let key_path  = dir.join("privkey.pem");
    if std::fs::write(&cert_path, &cert_data).is_err()
        || std::fs::write(&key_path, &key_data).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "error", "message": "证书写入失败" }))
        ).into_response();
    }
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    // 6. 入库
    let cert_path_str = cert_path.to_string_lossy().to_string();
    let key_path_str  = key_path.to_string_lossy().to_string();
    let not_after_dt  = parse_naive_dt(&not_after_str);
    let not_before_dt = parse_naive_dt(&not_before_str);

    let _ = sqlx::query(
        "INSERT INTO ssl_certs (domain, cert_path, key_path, issuer, not_before, not_after, auto_renew, acme_method)
         VALUES (?, ?, ?, ?, ?, ?, 1, 'manual')
         ON DUPLICATE KEY UPDATE cert_path=VALUES(cert_path), key_path=VALUES(key_path),
             issuer=VALUES(issuer), not_before=VALUES(not_before), not_after=VALUES(not_after), updated_at=NOW()"
    )
    .bind(&domain).bind(&cert_path_str).bind(&key_path_str)
    .bind(&issuer).bind(not_before_dt).bind(not_after_dt)
    .execute(&state.db_pool).await;

    // 热重载挂载到 SNI 解析器
    if let Err(e) = state.cert_resolver.add_cert(&domain, &cert_path_str, &key_path_str) {
        crate::log_error!("TLS_SNI", "证书已入库，但挂载 SNI 解析器失败: {}", e);
    } else {
        crate::log_success!("TLS_SNI", "热重载 SNI 证书: {}", domain);
    }

    let days = days_until_expiry(&not_after_str);
    (StatusCode::OK, Json(serde_json::json!({
        "status": "success",
        "message": format!("证书上传成功，到期: {}，剩余 {} 天", not_after_str, days),
        "domain": domain, "issuer": issuer,
        "not_after": not_after_str, "days_remaining": days,
    }))).into_response()
}

// ─── DELETE /ssl/certs/:domain ────────────────────────────────────────────────

pub async fn delete_cert(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Json<serde_json::Value> {
    if !validate_domain(&domain) {
        return Json(serde_json::json!({ "status": "error", "message": "无效的域名格式" }));
    }

    let dir = cert_dir(&domain);
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }

    let _ = sqlx::query("DELETE FROM ssl_certs WHERE domain = ?")
        .bind(&domain)
        .execute(&state.db_pool)
        .await;

    state.cert_resolver.remove_cert(&domain);
    crate::log_info!("TLS_SNI", "已从 SNI 卸载证书: {}", domain);

    Json(serde_json::json!({ "status": "success", "message": format!("证书 {} 已删除", domain) }))
}

// ─── GET /ssl/nginx-template/:domain ─────────────────────────────────────────
/// 生成该域名的 Nginx HTTPS server block 模板
pub async fn nginx_ssl_template(Path(domain): Path<String>) -> Json<serde_json::Value> {
    let base_domain = domain.trim_start_matches("*.");
    if !validate_domain(base_domain) {
        return Json(serde_json::json!({ "status": "error", "message": "无效的域名" }));
    }

    // certbot 默认存储在 live/<base_domain>/ 子目录
    let cert_path = format!("{}/live/{}/fullchain.pem", NGINX_CERTS_ROOT, base_domain);
    let key_path  = format!("{}/live/{}/privkey.pem",  NGINX_CERTS_ROOT, base_domain);

    // 通配符证书需要同时匹配根域名和所有子域名
    let server_name = if domain.starts_with("*.") {
        format!("{base_domain} *.{base_domain}")
    } else {
        base_domain.to_string()
    };

    let template = format!(
        r#"# HTTPS 站点: {domain}
server {{
    listen 443 ssl;
    http2  on;
    server_name {server_name};

    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};

    # 安全加固
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # HSTS (1 年，含子域名)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {{
        proxy_pass         http://mini-waf:48080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        "upgrade";
    }}
}}

# HTTP → HTTPS 强制跳转
server {{
    listen 80;
    server_name {server_name};
    return 301 https://$host$request_uri;
}}
"#,
        domain = domain,
        server_name = server_name,
        cert_path = cert_path,
        key_path = key_path,
    );

    Json(serde_json::json!({ "domain": domain, "template": template }))
}

// ─── ACME Config ───────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct AcmeConfig {
    pub email:              String,
    pub provider:           String,
    pub credentials_json:   String,  // JSON 字符串，客户端加密后存储
}

pub async fn get_acme_config(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let row = sqlx::query("SELECT email, provider, credentials_json FROM acme_config WHERE id = 1")
        .fetch_optional(&state.db_pool)
        .await
        .unwrap_or(None);

    match row {
        Some(r) => {
            use sqlx::Row;
            Json(serde_json::json!({
                "email":            r.get::<Option<String>, _>("email").unwrap_or_default(),
                "provider":         r.get::<Option<String>, _>("provider").unwrap_or_else(|| "http01".to_string()),
                "credentials_json": r.get::<Option<String>, _>("credentials_json").unwrap_or_default(),
            }))
        }
        None => Json(serde_json::json!({ "email": "", "provider": "http01", "credentials_json": "" })),
    }
}

pub async fn save_acme_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AcmeConfig>,
) -> Json<serde_json::Value> {
    // 校验 provider 白名单
    let allowed = ["http01", "dns_cloudflare", "dns_dnspod", "dns_aliyun", "dns_he"];
    if !allowed.contains(&payload.provider.as_str()) {
        return Json(serde_json::json!({ "status": "error", "message": "不支持的 ACME provider" }));
    }

    let _ = sqlx::query(
        "UPDATE acme_config SET email = ?, provider = ?, credentials_json = ? WHERE id = 1"
    )
    .bind(&payload.email)
    .bind(&payload.provider)
    .bind(&payload.credentials_json)
    .execute(&state.db_pool)
    .await;

    Json(serde_json::json!({ "status": "success", "message": "ACME 配置已保存" }))
}

// ─── ACME 账号 CRUD ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AcmeAccountPayload {
    pub name:        String,
    pub email:       String,
    #[serde(default = "default_acme_server")]
    pub acme_server: String,
    #[serde(default)]
    pub is_default:  bool,
    #[serde(default)]
    pub note:        String,
}
fn default_acme_server() -> String { "https://acme-v02.api.letsencrypt.org/directory".to_string() }

/// GET /ssl/acme/accounts — 列出所有 ACME 账号
pub async fn list_acme_accounts(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT id, name, email, acme_server, is_default, status, note, created_at
         FROM acme_accounts ORDER BY is_default DESC, created_at ASC"
    )
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let accounts: Vec<serde_json::Value> = rows.iter().map(|r| {
        use sqlx::Row;
        serde_json::json!({
            "id":          r.get::<u64, _>("id"),
            "name":        r.get::<String, _>("name"),
            "email":       r.get::<String, _>("email"),
            "acme_server": r.get::<String, _>("acme_server"),
            "is_default":  r.get::<i8, _>("is_default") != 0,
            "status":      r.get::<String, _>("status"),
            "note":        r.get::<Option<String>, _>("note").unwrap_or_default(),
            "created_at":  r.get::<Option<chrono::NaiveDateTime>, _>("created_at")
                            .map(|d| d.to_string()).unwrap_or_default(),
        })
    }).collect();

    Json(serde_json::json!({ "accounts": accounts }))
}

/// POST /ssl/acme/accounts — 新增 ACME 账号
pub async fn add_acme_account(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AcmeAccountPayload>,
) -> Json<serde_json::Value> {
    if payload.email.is_empty() {
        return Json(serde_json::json!({ "status": "error", "message": "邮箱不能为空" }));
    }
    if payload.is_default {
        let _ = sqlx::query("UPDATE acme_accounts SET is_default = 0")
            .execute(&state.db_pool).await;
    }
    let result = sqlx::query(
        "INSERT INTO acme_accounts (name, email, acme_server, is_default, note)
         VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&payload.name)
    .bind(&payload.email)
    .bind(&payload.acme_server)
    .bind(payload.is_default as i8)
    .bind(&payload.note)
    .execute(&state.db_pool).await;
    match result {
        Ok(r) => Json(serde_json::json!({ "status": "success", "message": "ACME 账号已创建", "id": r.last_insert_id() })),
        Err(e) => Json(serde_json::json!({ "status": "error", "message": format!("创建失败: {}", e) })),
    }
}

/// PUT /ssl/acme/accounts/:id — 更新 ACME 账号
pub async fn update_acme_account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(payload): Json<AcmeAccountPayload>,
) -> Json<serde_json::Value> {
    if payload.is_default {
        let _ = sqlx::query("UPDATE acme_accounts SET is_default = 0 WHERE id != ?")
            .bind(id).execute(&state.db_pool).await;
    }
    let _ = sqlx::query(
        "UPDATE acme_accounts SET name=?, email=?, acme_server=?, is_default=?, note=? WHERE id=?"
    )
    .bind(&payload.name)
    .bind(&payload.email)
    .bind(&payload.acme_server)
    .bind(payload.is_default as i8)
    .bind(&payload.note)
    .bind(id)
    .execute(&state.db_pool).await;
    Json(serde_json::json!({ "status": "success", "message": "ACME 账号已更新" }))
}

/// DELETE /ssl/acme/accounts/:id
pub async fn delete_acme_account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Json<serde_json::Value> {
    let _ = sqlx::query("DELETE FROM acme_accounts WHERE id = ?")
        .bind(id).execute(&state.db_pool).await;
    Json(serde_json::json!({ "status": "success", "message": "ACME 账号已删除" }))
}

/// POST /ssl/acme/accounts/:id/set-default
pub async fn set_default_acme_account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Json<serde_json::Value> {
    let _ = sqlx::query("UPDATE acme_accounts SET is_default = 0")
        .execute(&state.db_pool).await;
    let _ = sqlx::query("UPDATE acme_accounts SET is_default = 1 WHERE id = ?")
        .bind(id).execute(&state.db_pool).await;
    Json(serde_json::json!({ "status": "success", "message": "已设置为默认账号" }))
}

// ─── DNS 凭证 CRUD ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DnsCredentialPayload {
    pub name:             String,
    pub provider:         String,
    #[serde(default)]
    pub credentials_json: String,
    #[serde(default)]
    pub note:             String,
}

/// GET /ssl/dns-credentials
pub async fn list_dns_credentials(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = sqlx::query(
        "SELECT id, name, provider, credentials_json, note, created_at
         FROM dns_credentials ORDER BY created_at ASC"
    ).fetch_all(&state.db_pool).await.unwrap_or_default();

    let creds: Vec<serde_json::Value> = rows.iter().map(|r| {
        use sqlx::Row;
        serde_json::json!({
            "id":       r.get::<u64, _>("id"),
            "name":     r.get::<String, _>("name"),
            "provider": r.get::<String, _>("provider"),
            // 不对外返回凭证内容（安全）
            "note":     r.get::<Option<String>, _>("note").unwrap_or_default(),
            "created_at": r.get::<Option<chrono::NaiveDateTime>, _>("created_at")
                            .map(|d| d.to_string()).unwrap_or_default(),
        })
    }).collect();
    Json(serde_json::json!({ "credentials": creds }))
}

/// POST /ssl/dns-credentials
pub async fn add_dns_credential(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DnsCredentialPayload>,
) -> Json<serde_json::Value> {
    if payload.name.is_empty() || payload.provider.is_empty() {
        return Json(serde_json::json!({ "status": "error", "message": "名称和提供商不能为空" }));
    }
    let result = sqlx::query(
        "INSERT INTO dns_credentials (name, provider, credentials_json, note) VALUES (?, ?, ?, ?)"
    )
    .bind(&payload.name).bind(&payload.provider)
    .bind(&payload.credentials_json).bind(&payload.note)
    .execute(&state.db_pool).await;
    match result {
        Ok(r) => Json(serde_json::json!({ "status": "success", "message": "DNS 凭证已创建", "id": r.last_insert_id() })),
        Err(e) => Json(serde_json::json!({ "status": "error", "message": format!("创建失败: {}", e) })),
    }
}

/// PUT /ssl/dns-credentials/:id
pub async fn update_dns_credential(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
    Json(payload): Json<DnsCredentialPayload>,
) -> Json<serde_json::Value> {
    let _ = sqlx::query(
        "UPDATE dns_credentials SET name=?, provider=?, credentials_json=?, note=? WHERE id=?"
    )
    .bind(&payload.name).bind(&payload.provider)
    .bind(&payload.credentials_json).bind(&payload.note).bind(id)
    .execute(&state.db_pool).await;
    Json(serde_json::json!({ "status": "success", "message": "DNS 凭证已更新" }))
}

/// DELETE /ssl/dns-credentials/:id
pub async fn delete_dns_credential(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    let _ = sqlx::query("DELETE FROM dns_credentials WHERE id = ?")
        .bind(id).execute(&state.db_pool).await;
    Json(serde_json::json!({ "status": "success", "message": "DNS 凭证已删除" }))
}

/// GET /ssl/dns-credentials/:id/fields — 返回该凭证的字段（用于申请时回填，安全地读取）
pub async fn get_dns_credential_json(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    let row = sqlx::query("SELECT provider, credentials_json FROM dns_credentials WHERE id = ?")
        .bind(id).fetch_optional(&state.db_pool).await.unwrap_or(None);
    match row {
        Some(r) => {
            use sqlx::Row;
            Json(serde_json::json!({
                "provider":         r.get::<String, _>("provider"),
                "credentials_json": r.get::<Option<String>, _>("credentials_json").unwrap_or_default(),
            }))
        }
        None => Json(serde_json::json!({ "status": "error", "message": "凭证不存在" })),
    }
}

// ─── POST /ssl/certs/request — 通过 certbot 申请证书 ─────────────────────────
#[derive(Deserialize)]
pub struct CertRequestPayload {
    pub domain: String,
    #[serde(default)]
    pub wildcard: bool,
    /// ACME 账号 ID（不填则用默认账号）
    pub acme_account_id: Option<u64>,
    /// DNS 凭证 ID（不填则用 HTTP-01，通配符证书必须填）
    pub dns_credential_id: Option<u64>,
}

pub async fn request_cert(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CertRequestPayload>,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::body::Bytes;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    // ── 快速校验（在返回 stream 之前同步完成）──────────────────────────────
    if !validate_domain(&payload.domain) {
        let body = serde_json::json!({"type":"result","status":"error","message":"无效的域名格式"}).to_string() + "\n";
        return axum::response::Response::builder()
            .status(200)
            .header("Content-Type", "application/x-ndjson; charset=utf-8")
            .body(Body::from(body)).unwrap();
    }

    // ── 构建 certbot cmd_args（同步，快速）─────────────────────────────────
    // 这段逻辑保持与原来完全一致，只是改成同步路径，最终交给异步任务执行
    let build_result = build_certbot_cmd(&state, &payload).await;
    let (cmd_args, provider) = match build_result {
        Ok(v) => v,
        Err(msg) => {
            let body = serde_json::json!({"type":"result","status":"error","message":msg}).to_string() + "\n";
            return axum::response::Response::builder()
                .status(200)
                .header("Content-Type", "application/x-ndjson; charset=utf-8")
                .body(Body::from(body)).unwrap();
        }
    };

    let domain_arg   = payload.domain.clone();
    let is_wildcard  = payload.wildcard;
    let state_clone  = state.clone();

    // ── 创建 body 流 channel ───────────────────────────────────────────────
    let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(512);

    tokio::spawn(async move {
        // Helper: send a NDJSON line
        macro_rules! send_line {
            ($val:expr) => {{
                let line = $val.to_string() + "\n";
                let _ = body_tx.send(Ok(Bytes::from(line))).await;
            }};
        }

        // ── 启动 certbot 流式执行 ──────────────────────────────────────────
        let mut log_rx = match crate::api::nginx::docker_exec_output_stream(
            "mini-waf-certbot".to_string(),
            cmd_args,
        ).await {
            Ok(rx) => rx,
            Err(e) => {
                send_line!(serde_json::json!({"type":"result","status":"error",
                    "message": format!("启动 certbot 失败: {}", e)}));
                return;
            }
        };

        // ── 实时转发日志 ───────────────────────────────────────────────────
        let mut all_output = String::new();
        while let Some(text) = log_rx.recv().await {
            all_output.push_str(&text);
            send_line!(serde_json::json!({"type":"log","data": text}));
        }

        // ── 判断是否成功 ───────────────────────────────────────────────────
        let ok = all_output.to_lowercase().contains("successfully") ||
                 all_output.to_lowercase().contains("congratulations");
        if !ok {
            send_line!(serde_json::json!({"type":"result","status":"error",
                "message": format!("证书申请失败，certbot 输出:\n{}",
                    all_output.chars().take(2000).collect::<String>())}));
            return;
        }

        // ── 申请成功：读取证书信息，写库 ──────────────────────────────────
        let live_dir  = PathBuf::from(CERTS_ROOT).join("live").join(&domain_arg);
        let cert_path = live_dir.join("fullchain.pem");
        let (issuer, not_before, not_after) = parse_cert_file(&cert_path)
            .unwrap_or_else(|| ("Let's Encrypt".to_string(), "".to_string(), "".to_string()));

        let not_after_dt  = parse_naive_dt(&not_after);
        let not_before_dt = parse_naive_dt(&not_before);
        let cert_path_str = cert_path.to_string_lossy().to_string();
        let key_path_str  = live_dir.join("privkey.pem").to_string_lossy().to_string();

        let display_domain = if is_wildcard {
            format!("*.{}", domain_arg)
        } else {
            domain_arg.clone()
        };

        let _ = sqlx::query(
            "INSERT INTO ssl_certs (domain, cert_path, key_path, issuer, not_before, not_after, auto_renew, acme_method)
             VALUES (?, ?, ?, ?, ?, ?, 1, ?)
             ON DUPLICATE KEY UPDATE cert_path=VALUES(cert_path), key_path=VALUES(key_path),
                 issuer=VALUES(issuer), not_before=VALUES(not_before), not_after=VALUES(not_after),
                 acme_method=VALUES(acme_method), updated_at=NOW()"
        )
        .bind(&display_domain)
        .bind(&cert_path_str)
        .bind(&key_path_str)
        .bind(&issuer)
        .bind(not_before_dt)
        .bind(not_after_dt)
        .bind(&provider)
        .execute(&state_clone.db_pool)
        .await;

        if let Err(e) = state_clone.cert_resolver.add_cert(&display_domain, &cert_path_str, &key_path_str) {
            crate::log_error!("TLS_SNI", "ACME 证书已入库，但挂载 SNI 失败: {}", e);
        } else {
            crate::log_success!("TLS_SNI", "ACME 证书自动热重载 SNI: {}", display_domain);
        }

        let days = days_until_expiry(&not_after);
        send_line!(serde_json::json!({
            "type":    "result",
            "status":  "success",
            "message": format!("证书申请成功！到期时间: {}，剩余 {} 天", not_after, days),
            "domain":  display_domain,
            "not_after": not_after,
            "days_remaining": days,
        }));
    });

    let stream = ReceiverStream::new(body_rx);
    let body   = Body::from_stream(stream);
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/x-ndjson; charset=utf-8")
        .header("Cache-Control",     "no-cache")
        .header("X-Accel-Buffering", "no")   // 禁止 nginx 缓冲，保证实时推送
        .body(body)
        .unwrap()
}

// ─── build_certbot_cmd ────────────────────────────────────────────────────────
/// 构建 certbot 命令参数，并写入凭证 ini 文件（供 request_cert 流式接口调用）
async fn build_certbot_cmd(
    state: &Arc<AppState>,
    payload: &CertRequestPayload,
) -> Result<(Vec<String>, String), String> {
    // 1. 查找 ACME 账号（优先用指定 ID，否则用默认账号）
    let email = if let Some(acct_id) = payload.acme_account_id {
        let row = sqlx::query("SELECT email FROM acme_accounts WHERE id = ?")
            .bind(acct_id)
            .fetch_optional(&state.db_pool).await.unwrap_or(None);
        match row {
            Some(r) => { use sqlx::Row; r.get::<String, _>("email") }
            None => return Err("找不到指定的 ACME 账号".to_string()),
        }
    } else {
        let row = sqlx::query("SELECT email FROM acme_accounts WHERE is_default = 1 LIMIT 1")
            .fetch_optional(&state.db_pool).await.unwrap_or(None);
        match row {
            Some(r) => { use sqlx::Row; r.get::<String, _>("email") }
            None => {
                let cfg = sqlx::query("SELECT email FROM acme_config WHERE id = 1")
                    .fetch_optional(&state.db_pool).await.unwrap_or(None);
                match cfg {
                    Some(r) => { use sqlx::Row; r.get::<Option<String>, _>("email").unwrap_or_default() }
                    None => return Err("请先添加 ACME 账号".to_string()),
                }
            }
        }
    };

    if email.is_empty() {
        return Err("ACME 账号邮箱为空，请检查账号配置".to_string());
    }

    // 2. 查找 DNS 凭证（优先用指定 ID，否则 HTTP-01）
    let (provider, credentials_json) = if let Some(cred_id) = payload.dns_credential_id {
        let row = sqlx::query("SELECT provider, credentials_json FROM dns_credentials WHERE id = ?")
            .bind(cred_id).fetch_optional(&state.db_pool).await.unwrap_or(None);
        match row {
            Some(r) => {
                use sqlx::Row;
                (r.get::<String, _>("provider"),
                 r.get::<Option<String>, _>("credentials_json").unwrap_or_default())
            }
            None => return Err("找不到指定的 DNS 凭证".to_string()),
        }
    } else {
        ("http01".to_string(), String::new())
    };

    let domain_arg = payload.domain.clone();
    let certbot_domain = if payload.wildcard {
        format!("*.{}", domain_arg)
    } else {
        domain_arg.clone()
    };

    let mut cmd_args: Vec<String> = vec![
        "certbot".into(), "certonly".into(),
        "--non-interactive".into(),
        "--agree-tos".into(),
        "--email".into(), email.clone(),
        "--domain".into(), certbot_domain.clone(),
        "--force-renewal".into(),
    ];

    match provider.as_str() {
        "http01" => {
            cmd_args.push("--webroot".into());
            cmd_args.push("--webroot-path".into());
            cmd_args.push("/var/www/certbot".into());
        }
        "dns_cloudflare" => {
            let creds = parse_credentials(&credentials_json);
            let dns_token  = creds.get("CF_DNS_API_TOKEN").cloned().unwrap_or_default();
            let zone_token = creds.get("CF_ZONE_API_TOKEN").cloned().unwrap_or_else(|| dns_token.clone());
            if dns_token.is_empty() {
                return Err("请先在 DNS 凭证中填写 CF_DNS_API_TOKEN".to_string());
            }
            let _ = std::fs::create_dir_all(CERTS_TMP_HOST);
            let ini = if zone_token.is_empty() || zone_token == dns_token {
                format!("dns_cloudflare_api_token = {}\n", dns_token)
            } else {
                format!("dns_cloudflare_api_token = {}\ndns_cloudflare_zone_api_token = {}\n",
                    dns_token, zone_token)
            };
            let ini_host_path    = format!("{}/cf_{}.ini", CERTS_TMP_HOST,    domain_arg);
            let ini_certbot_path = format!("{}/cf_{}.ini", CERTS_TMP_CERTBOT, domain_arg);
            let _ = std::fs::write(&ini_host_path, &ini);
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&ini_host_path,
                    std::fs::Permissions::from_mode(0o600));
            }
            cmd_args.push("--dns-cloudflare".into());
            cmd_args.push("--dns-cloudflare-credentials".into());
            cmd_args.push(ini_certbot_path);
            cmd_args.push("--dns-cloudflare-propagation-seconds".into());
            cmd_args.push("60".into());
        }
        "dns_dnspod" => {
            let creds = parse_credentials(&credentials_json);
            let id  = creds.get("DP_Id").cloned().unwrap_or_default();
            let key = creds.get("DP_Key").cloned().unwrap_or_default();
            let _ = std::fs::create_dir_all(CERTS_TMP_HOST);
            let ini = format!("dns_dnspod_id = {}\ndns_dnspod_key = {}\n", id, key);
            let ini_host_path    = format!("{}/dnspod_{}.ini", CERTS_TMP_HOST,    domain_arg);
            let ini_certbot_path = format!("{}/dnspod_{}.ini", CERTS_TMP_CERTBOT, domain_arg);
            let _ = std::fs::write(&ini_host_path, ini);
            cmd_args.push("--dns-dnspod".into());
            cmd_args.push("--dns-dnspod-credentials".into());
            cmd_args.push(ini_certbot_path);
        }
        "dns_aliyun" => {
            let creds = parse_credentials(&credentials_json);
            let key    = creds.get("Ali_Key").cloned().unwrap_or_default();
            let secret = creds.get("Ali_Secret").cloned().unwrap_or_default();
            let _ = std::fs::create_dir_all(CERTS_TMP_HOST);
            let ini = format!("dns_aliyun_key = {}\ndns_aliyun_secret = {}\n", key, secret);
            let ini_host_path    = format!("{}/aliyun_{}.ini", CERTS_TMP_HOST,    domain_arg);
            let ini_certbot_path = format!("{}/aliyun_{}.ini", CERTS_TMP_CERTBOT, domain_arg);
            let _ = std::fs::write(&ini_host_path, ini);
            cmd_args.push("--dns-aliyun".into());
            cmd_args.push("--dns-aliyun-credentials".into());
            cmd_args.push(ini_certbot_path);
        }
        _ => return Err("不支持的验证方式".to_string()),
    }

    Ok((cmd_args, provider))
}

// ─── POST /ssl/certs/renew/:domain ───────────────────────────────────────────
pub async fn renew_cert(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    // 续签委托给流式的 request_cert
    let payload = CertRequestPayload {
        domain,
        wildcard: false,
        acme_account_id:   None,
        dns_credential_id: None,
    };
    request_cert(State(state), Json(payload)).await
}

// ─── POST /ssl/certs/toggle-renew/:domain ────────────────────────────────────
#[derive(Deserialize)]
pub struct ToggleRenewPayload {
    pub auto_renew: bool,
}

pub async fn toggle_auto_renew(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
    Json(payload): Json<ToggleRenewPayload>,
) -> Json<serde_json::Value> {
    if !validate_domain(&domain) {
        return Json(serde_json::json!({ "status": "error", "message": "无效域名" }));
    }
    let _ = sqlx::query("UPDATE ssl_certs SET auto_renew = ? WHERE domain = ?")
        .bind(payload.auto_renew as i8)
        .bind(&domain)
        .execute(&state.db_pool)
        .await;
    Json(serde_json::json!({ "status": "success", "auto_renew": payload.auto_renew }))
}

// ─── 辅助函数 ──────────────────────────────────────────────────────────────────
fn parse_credentials(json_str: &str) -> std::collections::HashMap<String, String> {
    serde_json::from_str(json_str).unwrap_or_default()
}

fn parse_naive_dt(s: &str) -> Option<chrono::NaiveDateTime> {
    use chrono::DateTime;
    DateTime::parse_from_rfc2822(s)
        .ok()
        .map(|d| d.naive_utc())
        .or_else(|| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok())
}

fn base64_encode_cert(der: &[u8]) -> String {
    use std::fmt::Write;
    let encoded = {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        let mut i = 0;
        while i + 3 <= der.len() {
            let n = ((der[i] as u32) << 16) | ((der[i+1] as u32) << 8) | (der[i+2] as u32);
            write!(result, "{}{}{}{}", alphabet[((n >> 18) & 63) as usize] as char, alphabet[((n >> 12) & 63) as usize] as char, alphabet[((n >> 6) & 63) as usize] as char, alphabet[(n & 63) as usize] as char).ok();
            i += 3;
        }
        let rem = der.len() - i;
        if rem == 1 {
            let n = (der[i] as u32) << 16;
            write!(result, "{}{}==", alphabet[((n >> 18) & 63) as usize] as char, alphabet[((n >> 12) & 63) as usize] as char).ok();
        } else if rem == 2 {
            let n = ((der[i] as u32) << 16) | ((der[i+1] as u32) << 8);
            write!(result, "{}{}{}=", alphabet[((n >> 18) & 63) as usize] as char, alphabet[((n >> 12) & 63) as usize] as char, alphabet[((n >> 6) & 63) as usize] as char).ok();
        }
        result
    };
    encoded
}
