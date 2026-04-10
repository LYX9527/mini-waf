use super::response::*;
use crate::config;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::{Response, StatusCode};
use std::path::{Path, PathBuf};

/// 根据文件扩展名推断 MIME 类型
fn guess_mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("webp") => "image/webp",
        Some("wasm") => "application/wasm",
        Some("xml") => "application/xml",
        Some("txt") => "text/plain; charset=utf-8",
        Some("map") => "application/json",
        Some("avif") => "image/avif",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// 安全路径解析，防止目录穿越攻击
/// 返回 None 表示路径无效或试图越出 root 目录
fn safe_path(root: &Path, request_path: &str) -> Option<PathBuf> {
    let root_canonical = root.canonicalize().ok()?;
    let cleaned = request_path.trim_start_matches('/');
    let joined = root.join(cleaned);

    match joined.canonicalize() {
        Ok(c) if c.starts_with(&root_canonical) => Some(c),
        Err(_) => {
            // 文件可能不存在，验证父目录是否在 root 内（支持 SPA 回退）
            if let Some(parent) = joined.parent() {
                if let Ok(pc) = parent.canonicalize() {
                    if pc.starts_with(&root_canonical) {
                        return Some(joined);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// 提供静态文件服务
///
/// - `root`: 路由映射的文件系统目录
/// - `suffix_path`: URL 路径中去掉路由前缀后的部分
/// - `is_spa`: 是否 SPA 模式（文件不存在时回退到 index.html）
pub async fn serve_static(
    root: &str,
    suffix_path: &str,
    is_spa: bool,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>> {
    let root_path = Path::new(root);

    let file_path = safe_path(root_path, suffix_path);

    let resolved = match file_path {
        Some(p) if p.is_file() => p,
        _ if is_spa => {
            // SPA 回退：服务 index.html
            root_path.join("index.html")
        }
        _ => {
            let html = render_error_page(
                404,
                "FILE NOT FOUND",
                "请求的静态资源不存在。",
                "#00f0ff",
                "static",
            );
            return create_response(html, StatusCode::NOT_FOUND);
        }
    };

    // 文件大小检查
    if let Ok(metadata) = tokio::fs::metadata(&resolved).await {
        if metadata.len() > config::MAX_STATIC_FILE_SIZE {
            let html = render_error_page(
                413,
                "FILE TOO LARGE",
                "请求的静态资源文件大小超过限制。",
                "#ff8800",
                "static",
            );
            return create_response(html, StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    let contents = match tokio::fs::read(&resolved).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let html = render_error_page(
                403,
                "ACCESS DENIED",
                "权限不足，无法读取请求的文件。",
                "#ff3366",
                "static",
            );
            return create_response(html, StatusCode::FORBIDDEN);
        }
        Err(_) => {
            let html = render_error_page(
                404,
                "FILE NOT FOUND",
                "请求的静态资源不存在。",
                "#00f0ff",
                "static",
            );
            return create_response(html, StatusCode::NOT_FOUND);
        }
    };

    let mime = guess_mime_type(&resolved);
    let body = Either::Right(Full::new(Bytes::from(contents)));
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static(mime),
    );

    Ok(resp)
}
