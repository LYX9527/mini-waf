use crate::state::AppState;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// 解析证书链
fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// 解析私钥
fn load_private_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    // 只取第一个私钥
    let key = rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "缺失或无效的私钥")
    })?;
    Ok(key)
}

/// 支持 SNI 热重载的动态证书解析器
#[derive(Debug, Clone)]
pub struct DynamicCertResolver {
    pub keys: Arc<std::sync::RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl DynamicCertResolver {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// 根据域名（包括通配符）加载并设置证书
    pub fn add_cert(&self, domain: &str, cert_path: &str, key_path: &str) -> std::io::Result<()> {
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        let private_key = any_supported_type(&key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let certified_key = Arc::new(CertifiedKey::new(certs, private_key));

        let mut map = self.keys.write().unwrap();
        map.insert(domain.to_lowercase(), certified_key);
        Ok(())
    }

    pub fn remove_cert(&self, domain: &str) {
        let mut map = self.keys.write().unwrap();
        map.remove(&domain.to_lowercase());
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let sni_lower = sni.to_lowercase();
        let map = self.keys.read().unwrap();
        
        // 精确匹配
        if let Some(cert) = map.get(&sni_lower) {
            return Some(cert.clone());
        }

        // 通配符匹配 (例如 *.abc.com 匹配 xyz.abc.com)
        let parts: Vec<&str> = sni_lower.split('.').collect();
        if parts.len() >= 2 {
            let wildcard = format!("*.{}", parts[1..].join("."));
            if let Some(cert) = map.get(&wildcard) {
                return Some(cert.clone());
            }
        }
        
        None
    }
}

/// 启动 HTTPS/TLS 网关
pub async fn start_tls_proxy_server(state: Arc<AppState>, resolver: Arc<DynamicCertResolver>, port: u16) {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    
    // 支持 ALPN，声明支持 HTTP/1.1
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            crate::log_error!("TLS_INIT", "无法绑定 HTTPS 端口 {}: {}", port, e);
            return;
        }
    };
    
    crate::log_success!("HTTPS_PROXY", "HTTPS 反向代理已启动，支持 SNI 动态路由，监听 {}", addr);

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(tuple) => tuple,
            Err(e) => {
                crate::log_error!("HTTPS_PROXY", "代理接收 TCP 错误: {}", e);
                continue;
            }
        };

        let state_clone = state.clone();
        let acceptor_clone = acceptor.clone();

        tokio::task::spawn(async move {
            match acceptor_clone.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req| {
                        super::handler::handle_request(req, remote_addr, state_clone.clone())
                    });

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        // 忽略客户端提前关闭连接的错误
                        if !err.to_string().contains("connection closed") {
                            crate::log_warn!("HTTPS_PROXY", "处理 HTTPS 请求错误: {:?}", err);
                        }
                    }
                }
                Err(err) => {
                    crate::log_warn!("HTTPS_PROXY", "TLS 握手失败 [{}]: {:?}", remote_addr, err);
                }
            }
        });
    }
}
