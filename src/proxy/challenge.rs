use super::handler::RequestContext;
use super::response::*;
use crate::state::{AppState, ClientFingerprint};
use http_body_util::BodyExt;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use uuid::Uuid;

/// 处理 WAF 内部质询端点 (/.waf/js_verify 和 /.waf/verify)
/// 调用者应先检查 ctx.is_waf_endpoint()
pub async fn handle_challenge_endpoint(
    ctx: &RequestContext,
    req: Request<Incoming>,
    state: &Arc<AppState>,
) -> Response<Either<Incoming, Full<Bytes>>> {
    if ctx.path_query == "/.waf/js_verify" {
        return handle_js_verify(ctx, req, state).await;
    }
    handle_captcha_verify(ctx, req, state).await
}

/// 处理 JS 质询验证 (POST /.waf/js_verify)
async fn handle_js_verify(
    ctx: &RequestContext,
    req: Request<Incoming>,
    state: &Arc<AppState>,
) -> Response<Either<Incoming, Full<Bytes>>> {
    let whole_body = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return render_challenge_failure(ctx);
        }
    };
    let body_str = String::from_utf8_lossy(&whole_body);

    let mut js_token = String::new();
    let mut redirect_url = String::from("/");
    for pair in body_str.split('&') {
        let mut parts = pair.split('=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k == "fp" {
                js_token = v.to_string();
            } else if k == "redirect" {
                redirect_url = percent_decode(v);
            }
        }
    }

    if !js_token.is_empty() {
        println!("✅ IP {} JS 质询通过！检测到真实浏览器引擎。", ctx.ip);

        let clearance_token = Uuid::new_v4().to_string();
        let fingerprint = ClientFingerprint {
            ip: ctx.ip.clone(),
            user_agent: ctx.user_agent.clone(),
        };
        state.verified_tokens.insert(clearance_token.clone(), fingerprint);
        state.rate_limiter.invalidate(&ctx.ip);
        state.captcha_answers.invalidate(&ctx.ip);

        let cookie_string = format!(
            "waf_clearance={}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
            clearance_token
        );
        Response::builder()
            .status(StatusCode::FOUND)
            .header(hyper::header::LOCATION, redirect_url)
            .header(hyper::header::SET_COOKIE, cookie_string)
            .body(Either::Right(Full::new(Bytes::from(""))))
            .unwrap()
    } else {
        println!("❌ IP {} JS 质询失败（Token 为空），拦截！", ctx.ip);
        render_challenge_failure(ctx)
    }
}

/// 处理数学验证码验证 (POST /.waf/verify)
async fn handle_captcha_verify(
    ctx: &RequestContext,
    req: Request<Incoming>,
    state: &Arc<AppState>,
) -> Response<Either<Incoming, Full<Bytes>>> {
    let whole_body = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return render_challenge_failure(ctx);
        }
    };
    let body_str = String::from_utf8_lossy(&whole_body);

    let mut user_answer: u32 = 0;
    let mut redirect_url = String::from("/");
    for pair in body_str.split('&') {
        let mut parts = pair.split('=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k == "answer" {
                user_answer = v.parse().unwrap_or(0);
            } else if k == "redirect" {
                redirect_url = percent_decode(v);
            }
        }
    }

    let expected_answer = match state.captcha_answers.get(&ctx.ip) {
        Some((n1, n2)) => n1 + n2,
        None => 999999, // 超时不存在，不可能答对
    };

    println!("用户提交: {}, 期望答案: {}", user_answer, expected_answer);

    if user_answer == expected_answer {
        println!("✅ IP {} 人机验证通过！颁发 Cookie 令牌。", ctx.ip);

        let clearance_token = Uuid::new_v4().to_string();
        let fingerprint = ClientFingerprint {
            ip: ctx.ip.clone(),
            user_agent: ctx.user_agent.clone(),
        };
        state.verified_tokens.insert(clearance_token.clone(), fingerprint);
        state.rate_limiter.invalidate(&ctx.ip);
        state.penalty_box.invalidate(&ctx.ip);
        state.captcha_answers.invalidate(&ctx.ip);

        let cookie_string = format!(
            "waf_clearance={}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
            clearance_token
        );
        Response::builder()
            .status(StatusCode::FOUND)
            .header(hyper::header::LOCATION, redirect_url)
            .header(hyper::header::SET_COOKIE, cookie_string)
            .body(Either::Right(Full::new(Bytes::from(""))))
            .unwrap()
    } else {
        println!("❌ IP {} 人机验证失败。", ctx.ip);
        let html = render_error_page(
            None,
            403,
            "VERIFICATION FAILED",
            "人机验证失败，请退回上一页重新尝试。",
            "#ff0033",
            &ctx.ip,
        );
        create_response(html, StatusCode::FORBIDDEN).unwrap()
    }
}

fn render_challenge_failure(ctx: &RequestContext) -> Response<Either<Incoming, Full<Bytes>>> {
    let html = render_error_page(
        None,
        403,
        "CHALLENGE FAILED",
        "环境安全检测失败，拒绝访问。",
        "#ff0033",
        &ctx.ip,
    );
    create_response(html, StatusCode::FORBIDDEN).unwrap()
}
