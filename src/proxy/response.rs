use chrono::Utc;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Response, StatusCode};

/// 通用响应类型
pub type ProxyResponse = Result<Response<Either<Incoming, Full<Bytes>>>, Box<dyn std::error::Error + Send + Sync>>;

/// 快速构造 HTML 拦截响应
pub fn create_response(html: String, status: StatusCode) -> ProxyResponse {
    let body = Either::Right(Full::new(Bytes::from(html)));
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(resp)
}

/// 统一的错误/拦截页面
pub fn render_error_page(
    custom_block_page: Option<&str>,
    status_code: u16,
    title: &str,
    message: &str,
    theme_color: &str,
    client_ip: &str,
) -> String {
    let trace_id = format!("WAF-{:X}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

    if let Some(custom) = custom_block_page {
        if !custom.trim().is_empty() {
            return custom
                .replace("{status_code}", &status_code.to_string())
                .replace("{title}", title)
                .replace("{message}", message)
                .replace("{client_ip}", client_ip)
                .replace("{trace_id}", &trace_id);
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_code} | WAF Intercepted</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #c9d1d9;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            overflow: hidden;
        }}
        .waf-card {{
            background: rgba(22, 27, 34, 0.8);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 40px 50px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 20px {theme_color}33;
            max-width: 500px;
            width: 100%;
            position: relative;
            backdrop-filter: blur(10px);
        }}
        .waf-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 4px;
            background: {theme_color};
            box-shadow: 0 0 15px {theme_color};
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
        }}
        .status-code {{
            font-size: 80px;
            font-weight: 800;
            margin: 0;
            color: {theme_color};
            text-shadow: 0 0 20px {theme_color}66;
            line-height: 1;
        }}
        .title {{ font-size: 24px; color: #fff; margin: 15px 0 10px; font-weight: 600; }}
        .message {{ font-size: 15px; color: #8b949e; margin-bottom: 35px; line-height: 1.6; }}
        .divider {{ height: 1px; background: #30363d; margin-bottom: 20px; }}
        .meta-info {{ font-size: 13px; color: #484f58; display: grid; gap: 8px; }}
        .meta-row {{ display: flex; justify-content: space-between; }}
        .meta-label {{ text-transform: uppercase; letter-spacing: 1px; }}
        .meta-value {{ color: #a5d6ff; }}
    </style>
</head>
<body>
    <div class="waf-card">
        <h1 class="status-code">{status_code}</h1>
        <div class="title">{title}</div>
        <div class="message">{message}</div>
        <div class="divider"></div>
        <div class="meta-info">
            <div class="meta-row">
                <span class="meta-label">Client IP</span>
                <span class="meta-value">{client_ip}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Ray ID</span>
                <span class="meta-value">{trace_id}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Engine</span>
                <span class="meta-value">Rust Mini-WAF v1.0</span>
            </div>
        </div>
    </div>
</body>
</html>"#,
        status_code = status_code,
        title = title,
        message = message,
        theme_color = theme_color,
        client_ip = client_ip,
        trace_id = trace_id
    )
}

/// 赛博朋克风格数学验证码页面
pub fn render_captcha_page(client_ip: &str, num1: u32, num2: u32, redirect_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF矩阵 | 质询</title>
    <style>
        body {{ background-color: #0b0f19; color: #c9d1d9; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .waf-card {{ background: rgba(22, 27, 34, 0.8); border: 1px solid #30363d; border-radius: 12px; padding: 40px; box-shadow: 0 0 30px rgba(0, 240, 255, 0.2); max-width: 450px; width: 90%; text-align: center; backdrop-filter: blur(10px); position: relative; }}
        .shield-icon {{ width: 60px; height: 70px; margin: 0 auto 15px; position: relative; border: 3px solid #00f0ff; border-top: none; border-radius: 0 0 50% 50% / 0 0 20px 20px; box-shadow: 0 0 15px rgba(0, 240, 255, 0.5), inset 0 0 10px rgba(0, 240, 255, 0.2); }}
        .shield-icon::before {{ content: ''; position: absolute; top: -10px; left: -3px; width: 66px; height: 10px; background: #0b0f19; border-left: 3px solid #00f0ff; border-right: 3px solid #00f0ff; border-radius: 5px 5px 0 0; }}
        .shield-icon::after {{ content: ''; position: absolute; top: 15px; left: 15px; width: 30px; height: 35px; border-left: 3px solid #00f0ff; border-bottom: 3px solid #00f0ff; border-radius: 0 0 5px 25px / 0 0 5px 15px; transform: rotate(-45deg); opacity: 0.7; }}
        .title {{ color: #00f0ff; font-size: 20px; font-weight: bold; margin-bottom: 12px; text-shadow: 0 0 10px rgba(0, 240, 255, 0.5); text-transform: uppercase; letter-spacing: 2px; }}
        .desc {{ color: #8b949e; font-size: 14px; line-height: 1.6; margin-bottom: 30px; }}
        .captcha-box {{ background: #0d1117; border: 1px solid #30363d; padding: 25px 20px; border-radius: 8px; margin-bottom: 25px; box-shadow: inset 0 0 15px rgba(0,0,0,0.3); }}
        .math-problem {{ font-size: 26px; color: #fff; letter-spacing: 3px; margin-bottom: 20px; font-weight: bold; }}
        .math-problem span {{ color: #00f0ff; text-shadow: 0 0 5px rgba(0, 240, 255, 0.3); }}
        input[type="number"] {{ background: #010409; border: 1px solid #30363d; color: #00f0ff; padding: 12px 15px; font-size: 20px; width: 120px; text-align: center; border-radius: 4px; outline: none; transition: all 0.3s ease; font-family: monospace; -moz-appearance: textfield; }}
        input[type="number"]::-webkit-outer-spin-button, input[type="number"]::-webkit-inner-spin-button {{ -webkit-appearance: none; margin: 0; }}
        input[type="number"]:focus {{ border-color: #00f0ff; box-shadow: 0 0 15px rgba(0, 240, 255, 0.4); }}
        button {{ background: transparent; border: 1px solid #00f0ff; color: #00f0ff; padding: 12px 35px; font-size: 15px; cursor: pointer; border-radius: 4px; transition: all 0.3s ease; text-transform: uppercase; font-family: monospace; font-weight: bold; margin-top: 10px; letter-spacing: 1px; }}
        button:hover {{ background: #00f0ff; color: #000; box-shadow: 0 0 25px rgba(0, 240, 255, 0.7); text-shadow: none; }}
        .ip-info {{ margin-top: 35px; font-size: 11px; color: #484f58; letter-spacing: 1px; }}
    </style>
</head>
<body>
    <div class="waf-card">
        <div class="shield-icon"></div>
        <div class="title">Security Challenge</div>
        <div class="desc">系统检测到您的网络请求频率异常。<br>请证明您是人类，以继续访问该网站。</div>

        <form action="/.waf/verify" method="POST">
            <input type="hidden" name="redirect" value="{redirect_url}">

            <div class="captcha-box">
                <div class="math-problem">{num1} + {num2} = ?</div>
                <input type="number" name="answer" required autocomplete="off" placeholder="答案">
            </div>
            <button type="submit">Verify Now / 提交验证</button>
        </form>

        <div class="ip-info">Client IP: {client_ip} | Rust WAF 矩阵安全防御系统 v1.0</div>
    </div>
</body>
</html>"#,
        redirect_url = redirect_url,
        num1 = num1,
        num2 = num2,
        client_ip = client_ip
    )
}

/// JS 无感质询页面 (Cloudflare 5 秒盾风格)
/// BUG FIX: 移除了重复的 <form> 标签，确保 redirect 字段正确提交
pub fn render_js_challenge_page(client_ip: &str, redirect_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checking your browser...</title>
    <style>
        body {{ background-color: #0b0f19; color: #c9d1d9; font-family: 'SFMono-Regular', Consolas, monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; flex-direction: column; }}
        .spinner {{ width: 50px; height: 50px; border: 3px solid rgba(0, 240, 255, 0.1); border-radius: 50%; border-top-color: #00f0ff; animation: spin 1s ease-in-out infinite; margin-bottom: 30px; box-shadow: 0 0 15px rgba(0,240,255,0.2); }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        h2 {{ color: #00f0ff; font-weight: normal; letter-spacing: 1px; font-size: 20px; }}
        p {{ color: #8b949e; font-size: 14px; max-width: 400px; text-align: center; line-height: 1.6; }}
    </style>
</head>
<body>
    <div class="spinner"></div>
    <h2>WAF 防御矩阵正在验证您的环境</h2>
    <p>请稍候，这通常需要几秒钟。我们将验证您使用的是安全的浏览器而非自动化脚本。</p>
    <p style="font-size: 12px; margin-top: 20px; opacity: 0.5;">Client IP: {client_ip}</p>

    <form id="challenge-form" action="/.waf/js_verify" method="POST" style="display:none;">
        <input type="hidden" name="fp" id="fp_input" value="">
        <input type="hidden" name="redirect" value="{redirect_url}">
    </form>
    <script>
        setTimeout(function() {{
            var screenData = window.screen ? (window.screen.width + "x" + window.screen.height + "-" + window.screen.colorDepth) : "headless";
            var timezone = new Date().getTimezoneOffset();
            var rawFingerprint = screenData + "|" + timezone;
            var jsToken = btoa(rawFingerprint);
            document.getElementById('fp_input').value = jsToken;
            document.getElementById('challenge-form').submit();
        }}, {delay_ms});
    </script>
</body>
</html>"#,
        client_ip = client_ip,
        redirect_url = redirect_url,
        delay_ms = crate::config::JS_CHALLENGE_DELAY_MS
    )
}

/// 迷你 URL 解码器 (处理表单提交的 %2F 等字符)
pub fn percent_decode(input: &str) -> String {
    let mut res = String::new();
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                res.push(byte as char);
            } else {
                res.push('%');
                res.push_str(&hex);
            }
        } else if c == '+' {
            res.push(' ');
        } else {
            res.push(c);
        }
    }
    res
}
