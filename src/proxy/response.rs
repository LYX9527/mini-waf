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
    <title>WAF 防御矩阵 | 安全质询</title>
    <style>
        body {{ background-color: #050505; color: #e5e7eb; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-image: radial-gradient(circle at center, #111827 0%, #000000 100%); }}
        .waf-card {{ background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(55, 65, 81, 0.5); border-radius: 16px; padding: 48px 40px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 40px rgba(0, 240, 255, 0.1); max-width: 420px; width: 90%; text-align: center; backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); position: relative; overflow: hidden; }}
        .waf-card::before {{ content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 4px; background: linear-gradient(90deg, #00f0ff, #7000ff); }}
        .shield-icon {{ width: 56px; height: 56px; margin: 0 auto 24px; display: block; filter: drop-shadow(0 0 12px rgba(0,240,255,0.6)); animation: pulse 2.5s infinite ease-in-out; }}
        @keyframes pulse {{ 0% {{ filter: drop-shadow(0 0 8px rgba(0,240,255,0.4)); transform: scale(1); }} 50% {{ filter: drop-shadow(0 0 16px rgba(0,240,255,0.8)); transform: scale(1.05); }} 100% {{ filter: drop-shadow(0 0 8px rgba(0,240,255,0.4)); transform: scale(1); }} }}
        .title {{ color: #f9fafb; font-size: 22px; font-weight: 700; margin-bottom: 12px; letter-spacing: 0.5px; }}
        .desc {{ color: #9ca3af; font-size: 14px; line-height: 1.6; margin-bottom: 32px; }}
        .desc strong {{ color: #e5e7eb; }}
        .captcha-container {{ background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(75, 85, 99, 0.4); padding: 24px; border-radius: 12px; margin-bottom: 30px; box-shadow: inset 0 2px 4px rgba(0,0,0,0.5); display: flex; flex-direction: column; align-items: center; }}
        canvas {{ background-color: rgba(17, 24, 39, 0.4); border: 1px dashed rgba(75, 85, 99, 0.6); border-radius: 8px; margin-bottom: 24px; user-select: none; pointer-events: none; }}
        input[type="number"] {{ background: rgba(17, 24, 39, 0.8); border: 1px solid rgba(75, 85, 99, 0.6); color: #00f0ff; padding: 14px 16px; font-size: 24px; width: 140px; text-align: center; border-radius: 8px; outline: none; transition: all 0.3s ease; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-weight: bold; -moz-appearance: textfield; }}
        input[type="number"]::-webkit-outer-spin-button, input[type="number"]::-webkit-inner-spin-button {{ -webkit-appearance: none; margin: 0; }}
        input[type="number"]:focus {{ border-color: #00f0ff; box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.2); }}
        button {{ background: linear-gradient(135deg, #00f0ff 0%, #0099ff 100%); border: none; color: #000; padding: 14px 40px; font-size: 16px; cursor: pointer; border-radius: 8px; transition: all 0.3s ease; font-weight: 700; width: 100%; letter-spacing: 0.5px; box-shadow: 0 4px 12px rgba(0, 240, 255, 0.3); }}
        button:hover {{ transform: translateY(-2px); box-shadow: 0 6px 16px rgba(0, 240, 255, 0.4); }}
        button:active {{ transform: translateY(0); }}
        .ip-info {{ margin-top: 32px; font-size: 12px; color: #6b7280; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    </style>
</head>
<body>
    <div class="waf-card">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" class="shield-icon" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="M12 8v4"></path>
            <circle cx="12" cy="16" r="1.5"></circle>
        </svg>
        <div class="title">Security Challenge</div>
        <div class="desc">系统检测到您的网络请求频率过快。<br>请计算下方结果以证明您是<strong>真实用户</strong>。</div>

        <form action="/.waf/verify" method="POST">
            <input type="hidden" name="redirect" value="{redirect_url}">

            <div class="captcha-container">
                <canvas id="captchaCanvas" width="240" height="70"></canvas>
                <input type="number" name="answer" required autocomplete="off" placeholder="输入答案" autofocus>
            </div>
            <button type="submit">Verify Now / 提交验证</button>
        </form>

        <div class="ip-info">Client IP: {client_ip} | Rust WAF 矩阵</div>
    </div>

    <script>
        (function() {{
            var n1 = parseInt('{num1}', 10);
            var n2 = parseInt('{num2}', 10);
            var operator = String.fromCharCode(43);
            var t = n1 + ' ' + operator + ' ' + n2 + ' = ?';

            var c = document.getElementById('captchaCanvas');
            var ctx = c.getContext('2d');

            // Draw noise lines
            for(var i=0; i<8; i++) {{
                ctx.strokeStyle = 'rgba(0, 240, 255, ' + (Math.random()*0.3 + 0.1) + ')';
                ctx.lineWidth = Math.random() * 2 + 1;
                ctx.beginPath();
                ctx.moveTo(Math.random() * 240, Math.random() * 70);
                ctx.lineTo(Math.random() * 240, Math.random() * 70);
                ctx.stroke();
            }}

            // Draw noise dots
            for(var i=0; i<40; i++) {{
                ctx.fillStyle = 'rgba(0, 240, 255, ' + (Math.random()*0.3 + 0.1) + ')';
                ctx.beginPath();
                ctx.arc(Math.random() * 240, Math.random() * 70, Math.random() * 2, 0, Math.PI*2);
                ctx.fill();
            }}

            ctx.font = 'bold 34px monospace';
            ctx.fillStyle = '#00f0ff';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';

            var xOffset = 25;
            for (var i = 0; i < t.length; i++) {{
                ctx.save();
                ctx.translate(xOffset, 35 + (Math.random() * 8 - 4));
                ctx.rotate((Math.random() * 0.3 - 0.15));
                ctx.shadowColor = 'rgba(0, 240, 255, 0.4)';
                ctx.shadowBlur = 5;
                ctx.fillText(t.charAt(i), 0, 0);
                ctx.restore();

                xOffset += (t.charAt(i) === ' ' ? 12 : (t.charAt(i) === operator ? 22 : 24));
            }}
        }})();
    </script>
</body>
</html>"#,
        color = "#00f0ff",
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
