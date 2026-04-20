/// 内置 OWASP Top10 + 现代攻击检测规则集
/// 分类覆盖: SQL 注入、XSS、路径穿越、RCE/命令注入、SSRF、SSTI、
///           XXE、LDAP 注入、CRLF 注入、反序列化、Log4Shell/Spring4Shell、
///           Prototype Pollution、扫描器指纹、敏感文件探测、Webshell、
///           Header 注入、Cookie 注入、Body 层攻击
///
/// 规则总条数: ~200+
/// 匹配支持: Contains (关键词) / Regex (正则)

/// 单条规则定义（keyword, target_field, match_type, description）
pub struct BuiltinRule {
    pub keyword: &'static str,
    pub target_field: &'static str,
    pub match_type: &'static str,
    pub description: &'static str,
}

/// 返回完整的内置默认规则集
pub fn builtin_default_rules() -> Vec<serde_json::Value> {
    ALL_RULES.iter().map(|r| {
        serde_json::json!({
            "keyword": r.keyword,
            "target_field": r.target_field,
            "match_type": r.match_type,
            "description": r.description
        })
    }).collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  宏：批量定义规则（减少样板代码）
// ═══════════════════════════════════════════════════════════════════════════════
macro_rules! rules {
    ( $( ($kw:expr, $field:expr, $mt:expr, $desc:expr) ),* $(,)? ) => {
        &[ $( BuiltinRule { keyword: $kw, target_field: $field, match_type: $mt, description: $desc }, )* ]
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  完整规则集（约 200+ 条）
// ═══════════════════════════════════════════════════════════════════════════════
static ALL_RULES: &[BuiltinRule] = rules![

    // ─── 1. SQL 注入 (SQLi) ─────────────────────────────────────────────────────
    // 1.1 经典关键词
    ("' or '1'='1",           "URL",  "Contains", "SQLi - 万能密码"),
    ("' or 1=1",              "URL",  "Contains", "SQLi - 永真条件变体"),
    ("' or ''='",             "URL",  "Contains", "SQLi - 空串比较"),
    ("union select",          "URL",  "Contains", "SQLi - UNION 查询"),
    ("union all select",      "URL",  "Contains", "SQLi - UNION ALL"),
    ("drop table",            "URL",  "Contains", "SQLi - DROP TABLE"),
    ("drop database",         "URL",  "Contains", "SQLi - DROP DATABASE"),
    ("insert into",           "URL",  "Contains", "SQLi - INSERT"),
    ("update set",            "URL",  "Contains", "SQLi - UPDATE SET"),
    ("delete from",           "URL",  "Contains", "SQLi - DELETE FROM"),
    ("exec(",                 "URL",  "Contains", "SQLi - exec 函数"),
    ("execute(",              "URL",  "Contains", "SQLi - execute 函数"),
    ("xp_cmdshell",           "URL",  "Contains", "SQLi - MSSQL xp_cmdshell"),
    ("sp_executesql",         "URL",  "Contains", "SQLi - MSSQL sp_executesql"),
    ("or 1=1",                "URL",  "Contains", "SQLi - 永真条件"),
    ("and 1=1",               "URL",  "Contains", "SQLi - 永真探测"),
    ("and 1=2",               "URL",  "Contains", "SQLi - 布尔盲注假条件"),
    ("-- ",                   "URL",  "Contains", "SQLi - SQL 注释符"),
    ("#",                     "URL",  "Contains", "SQLi - MySQL 注释符"),
    (";select ",              "URL",  "Contains", "SQLi - 堆叠查询"),
    ("waitfor delay",         "URL",  "Contains", "SQLi - MSSQL 时间盲注"),
    ("benchmark(",            "URL",  "Contains", "SQLi - MySQL 时间盲注"),
    ("sleep(",                "URL",  "Contains", "SQLi - MySQL sleep 盲注"),
    ("extractvalue(",         "URL",  "Contains", "SQLi - MySQL 报错注入"),
    ("updatexml(",            "URL",  "Contains", "SQLi - MySQL 报错注入"),
    ("load_file(",            "URL",  "Contains", "SQLi - MySQL 读文件"),
    ("into outfile",          "URL",  "Contains", "SQLi - MySQL 写文件"),
    ("into dumpfile",         "URL",  "Contains", "SQLi - MySQL 写文件"),
    ("information_schema",    "URL",  "Contains", "SQLi - 元数据库探测"),
    ("pg_sleep(",             "URL",  "Contains", "SQLi - PostgreSQL 时间盲注"),
    ("chr(",                  "URL",  "Contains", "SQLi - PostgreSQL 字符函数"),
    ("convert(",              "URL",  "Contains", "SQLi - MSSQL convert"),
    ("char(",                 "URL",  "Contains", "SQLi - 字符编码绕过"),
    ("concat(",               "URL",  "Contains", "SQLi - 拼接函数"),
    ("group_concat(",         "URL",  "Contains", "SQLi - 多行拼接"),
    ("having 1=1",            "URL",  "Contains", "SQLi - HAVING 注入"),
    ("order by 1",            "URL",  "Contains", "SQLi - ORDER BY 列数探测"),

    // 1.2 Body 层 SQL 注入（POST 参数）
    ("union select",          "Body", "Contains", "SQLi - Body UNION 查询"),
    ("' or '1'='1",           "Body", "Contains", "SQLi - Body 万能密码"),
    ("or 1=1",                "Body", "Contains", "SQLi - Body 永真条件"),
    ("drop table",            "Body", "Contains", "SQLi - Body DROP TABLE"),
    ("insert into",           "Body", "Contains", "SQLi - Body INSERT"),
    ("sleep(",                "Body", "Contains", "SQLi - Body sleep 盲注"),
    ("benchmark(",            "Body", "Contains", "SQLi - Body benchmark 盲注"),

    // 1.3 Cookie 层 SQL 注入
    ("' or '1'='1",           "Cookie", "Contains", "SQLi - Cookie 注入"),
    ("union select",          "Cookie", "Contains", "SQLi - Cookie UNION"),
    ("or 1=1",                "Cookie", "Contains", "SQLi - Cookie 永真条件"),

    // ─── 2. XSS 跨站脚本 ───────────────────────────────────────────────────────
    // 2.1 标签注入
    ("<script",               "URL",  "Contains", "XSS - script 标签"),
    ("<script",               "Body", "Contains", "XSS - Body script 标签"),
    ("</script>",             "URL",  "Contains", "XSS - script 闭合标签"),
    ("<iframe",               "URL",  "Contains", "XSS - iframe 注入"),
    ("<iframe",               "Body", "Contains", "XSS - Body iframe 注入"),
    ("<object",               "URL",  "Contains", "XSS - object 标签"),
    ("<embed",                "URL",  "Contains", "XSS - embed 标签"),
    ("<svg",                  "URL",  "Contains", "XSS - SVG 注入"),
    ("<svg",                  "Body", "Contains", "XSS - Body SVG 注入"),
    ("<math",                 "URL",  "Contains", "XSS - MathML 注入"),
    ("<img src=x",            "URL",  "Contains", "XSS - img src 注入"),
    ("<body onload",          "URL",  "Contains", "XSS - body onload"),
    ("<input",                "URL",  "Contains", "XSS - input 注入"),

    // 2.2 伪协议 / 事件处理
    ("javascript:",           "URL",  "Contains", "XSS - javascript: 伪协议"),
    ("vbscript:",             "URL",  "Contains", "XSS - vbscript: 伪协议"),
    ("data:text/html",        "URL",  "Contains", "XSS - data: HTML 注入"),
    ("onerror=",              "URL",  "Contains", "XSS - onerror 事件"),
    ("onload=",               "URL",  "Contains", "XSS - onload 事件"),
    ("onclick=",              "URL",  "Contains", "XSS - onclick 事件"),
    ("onmouseover=",          "URL",  "Contains", "XSS - onmouseover 事件"),
    ("onfocus=",              "URL",  "Contains", "XSS - onfocus 事件"),
    ("onblur=",               "URL",  "Contains", "XSS - onblur 事件"),
    ("oninput=",              "URL",  "Contains", "XSS - oninput 事件"),
    ("onchange=",             "URL",  "Contains", "XSS - onchange 事件"),
    ("onsubmit=",             "URL",  "Contains", "XSS - onsubmit 事件"),

    // 2.3 DOM / 函数
    ("alert(",                "URL",  "Contains", "XSS - alert 弹窗"),
    ("confirm(",              "URL",  "Contains", "XSS - confirm 弹窗"),
    ("prompt(",               "URL",  "Contains", "XSS - prompt 弹窗"),
    ("document.cookie",       "URL",  "Contains", "XSS - cookie 窃取"),
    ("document.write(",       "URL",  "Contains", "XSS - document.write"),
    ("document.location",     "URL",  "Contains", "XSS - 页面跳转"),
    ("window.location",       "URL",  "Contains", "XSS - 窗口跳转"),
    ("eval(",                 "URL",  "Contains", "XSS/RCE - eval 执行"),
    ("eval(",                 "Body", "Contains", "XSS/RCE - Body eval"),
    ("settimeout(",           "URL",  "Contains", "XSS - setTimeout 执行"),
    ("setinterval(",          "URL",  "Contains", "XSS - setInterval 执行"),
    ("function(",             "URL",  "Contains", "XSS - Function 构造器"),
    ("string.fromcharcode(",  "URL",  "Contains", "XSS - 字符编码绕过"),
    ("atob(",                 "URL",  "Contains", "XSS - Base64 解码绕过"),

    // 2.4 Header 层 XSS
    ("<script",               "Header", "Contains", "XSS - Header script 注入"),
    ("javascript:",           "Header", "Contains", "XSS - Header 伪协议"),

    // 2.5 Cookie 层 XSS
    ("<script",               "Cookie", "Contains", "XSS - Cookie script 注入"),

    // ─── 3. 路径穿越 / LFI ─────────────────────────────────────────────────────
    ("../",                   "URL",  "Contains", "路径穿越攻击"),
    ("..\\",                  "URL",  "Contains", "路径穿越 (Windows)"),
    ("..%2f",                 "URL",  "Contains", "路径穿越 - 编码变体"),
    ("%2e%2e%2f",             "URL",  "Contains", "路径穿越 - 双层编码"),
    ("%2e%2e/",               "URL",  "Contains", "路径穿越 - 混合编码"),
    ("..%255c",               "URL",  "Contains", "路径穿越 - 双重编码 IIS"),
    ("/etc/passwd",           "URL",  "Contains", "LFI - 读取 passwd"),
    ("/etc/shadow",           "URL",  "Contains", "LFI - 读取 shadow"),
    ("/etc/hosts",            "URL",  "Contains", "LFI - 读取 hosts"),
    ("/proc/self/environ",    "URL",  "Contains", "LFI - proc 进程环境"),
    ("/proc/self/cmdline",    "URL",  "Contains", "LFI - proc 命令行"),
    ("c:\\windows",           "URL",  "Contains", "路径穿越 - Windows 系统路径"),
    ("c:\\boot.ini",          "URL",  "Contains", "路径穿越 - Windows boot.ini"),
    ("web.config",            "URL",  "Contains", "LFI - IIS web.config"),
    ("/var/log/",             "URL",  "Contains", "LFI - 日志文件读取"),

    // ─── 4. RCE / 命令注入 (OS Command Injection) ───────────────────────────────
    ("cmd.exe",               "URL",  "Contains", "RCE - Windows cmd"),
    ("powershell",            "URL",  "Contains", "RCE - PowerShell"),
    ("/bin/sh",               "URL",  "Contains", "RCE - Unix shell"),
    ("/bin/bash",             "URL",  "Contains", "RCE - bash"),
    ("wget http",             "URL",  "Contains", "RCE - wget 下载"),
    ("curl http",             "URL",  "Contains", "RCE - curl 下载"),
    ("nc -e",                 "URL",  "Contains", "RCE - netcat 反弹 shell"),
    ("ncat ",                 "URL",  "Contains", "RCE - ncat"),
    ("; ls",                  "URL",  "Contains", "RCE - 分号拼接 ls"),
    ("| cat ",                "URL",  "Contains", "RCE - 管道拼接 cat"),
    ("&& cat ",               "URL",  "Contains", "RCE - AND 拼接 cat"),
    ("|| cat ",               "URL",  "Contains", "RCE - OR 拼接 cat"),
    ("`id`",                  "URL",  "Contains", "RCE - 反引号执行"),
    ("$(id)",                 "URL",  "Contains", "RCE - 子命令执行"),
    ("$(whoami)",             "URL",  "Contains", "RCE - whoami 探测"),
    ("python -c",             "URL",  "Contains", "RCE - Python 执行"),
    ("perl -e",               "URL",  "Contains", "RCE - Perl 执行"),
    ("ruby -e",               "URL",  "Contains", "RCE - Ruby 执行"),
    ("node -e",               "URL",  "Contains", "RCE - Node.js 执行"),

    // 4.1 PHP 特有
    ("phpinfo()",             "URL",  "Contains", "PHP 信息泄露"),
    ("passthru(",             "URL",  "Contains", "PHP RCE - passthru"),
    ("system(",               "URL",  "Contains", "PHP RCE - system"),
    ("shell_exec(",           "URL",  "Contains", "PHP RCE - shell_exec"),
    ("popen(",                "URL",  "Contains", "PHP RCE - popen"),
    ("proc_open(",            "URL",  "Contains", "PHP RCE - proc_open"),
    ("assert(",               "URL",  "Contains", "PHP RCE - assert"),
    ("preg_replace",          "URL",  "Contains", "PHP RCE - preg_replace /e"),
    ("base64_decode(",        "URL",  "Contains", "PHP - base64 解码执行"),
    ("file_get_contents(",    "URL",  "Contains", "PHP - 文件读取"),
    ("file_put_contents(",    "URL",  "Contains", "PHP - 文件写入"),
    ("include(",              "URL",  "Contains", "PHP RFI - include"),
    ("require(",              "URL",  "Contains", "PHP RFI - require"),
    ("include_once(",         "URL",  "Contains", "PHP RFI - include_once"),

    // 4.2 Body 层命令注入
    ("; ls",                  "Body", "Contains", "RCE - Body 分号拼接 ls"),
    ("| cat ",                "Body", "Contains", "RCE - Body 管道拼接"),
    ("$(whoami)",             "Body", "Contains", "RCE - Body whoami"),
    ("`id`",                  "Body", "Contains", "RCE - Body 反引号执行"),
    ("system(",               "Body", "Contains", "RCE - Body system 调用"),

    // ─── 5. SSRF 服务端请求伪造 ─────────────────────────────────────────────────
    ("169.254.169.254",       "URL",  "Contains", "SSRF - AWS/Azure 元数据"),
    ("metadata.google.internal", "URL", "Contains", "SSRF - GCP 元数据"),
    ("100.100.100.200",       "URL",  "Contains", "SSRF - 阿里云元数据"),
    ("file:///",              "URL",  "Contains", "SSRF - 本地文件读取"),
    ("gopher://",             "URL",  "Contains", "SSRF - Gopher 协议"),
    ("dict://",               "URL",  "Contains", "SSRF - Dict 协议"),
    ("ftp://",                "URL",  "Contains", "SSRF - FTP 协议"),
    ("ldap://",               "URL",  "Contains", "SSRF - LDAP 协议"),
    ("sftp://",               "URL",  "Contains", "SSRF - SFTP 协议"),
    ("tftp://",               "URL",  "Contains", "SSRF - TFTP 协议"),
    ("127.0.0.1",             "URL",  "Contains", "SSRF - 本地回环地址"),
    ("0.0.0.0",               "URL",  "Contains", "SSRF - 全零地址"),
    ("localhost",             "Body", "Contains", "SSRF - Body localhost"),
    ("169.254.169.254",       "Body", "Contains", "SSRF - Body AWS 元数据"),

    // ─── 6. SSTI 服务端模板注入 ─────────────────────────────────────────────────
    ("{{",                    "URL",  "Contains", "SSTI - 双花括号模板注入"),
    ("${",                    "URL",  "Contains", "SSTI - 美元花括号表达式"),
    ("#{",                    "URL",  "Contains", "SSTI - Spring EL 表达式"),
    ("{{7*7}}",               "URL",  "Contains", "SSTI - Jinja2/Twig 探测"),
    ("{{7*7}}",               "Body", "Contains", "SSTI - Body Jinja2 探测"),
    ("${7*7}",                "URL",  "Contains", "SSTI - Freemarker 探测"),
    ("#{7*7}",                "URL",  "Contains", "SSTI - Thymeleaf 探测"),
    ("<%=",                   "URL",  "Contains", "SSTI - ERB/JSP 模板探测"),
    ("__class__",             "URL",  "Contains", "SSTI - Python MRO 链"),
    ("__subclasses__",        "URL",  "Contains", "SSTI - Python 子类遍历"),
    ("__import__",            "URL",  "Contains", "SSTI - Python import 执行"),
    ("__builtins__",          "URL",  "Contains", "SSTI - Python 内置模块"),

    // ─── 7. XXE XML 外部实体注入 ────────────────────────────────────────────────
    ("<!doctype",             "Body", "Contains", "XXE - DOCTYPE 声明"),
    ("<!entity",              "Body", "Contains", "XXE - ENTITY 声明"),
    ("system \"file:",        "Body", "Contains", "XXE - 文件读取"),
    ("system \"http:",        "Body", "Contains", "XXE - 外部 HTTP 引用"),
    ("xinclude",              "Body", "Contains", "XXE - XInclude 包含"),
    ("<?xml",                 "Body", "Contains", "XXE - XML 声明（可疑 Body）"),

    // ─── 8. LDAP 注入 ──────────────────────────────────────────────────────────
    (")(cn=*",                "URL",  "Contains", "LDAP 注入 - 通配符查询"),
    (")(uid=*",               "URL",  "Contains", "LDAP 注入 - UID 通配"),
    ("*()|&",                 "URL",  "Contains", "LDAP 注入 - 逻辑操作符"),
    (")(|(password=*",        "URL",  "Contains", "LDAP 注入 - 密码遍历"),

    // ─── 9. CRLF 注入 / HTTP 响应拆分 ──────────────────────────────────────────
    ("%0d%0a",                "URL",  "Contains", "CRLF 注入 - URL 编码"),
    ("%0D%0A",                "URL",  "Contains", "CRLF 注入 - 大写编码"),
    ("\\r\\n",                "URL",  "Contains", "CRLF 注入 - 转义序列"),
    ("%0d%0aset-cookie:",     "URL",  "Contains", "CRLF - Cookie 注入"),
    ("%0d%0alocation:",       "URL",  "Contains", "CRLF - 重定向劫持"),
    ("%0d%0a%0d%0a",          "URL",  "Contains", "CRLF - 响应拆分"),

    // ─── 10. 反序列化攻击 ──────────────────────────────────────────────────────
    ("rO0AB",                 "Body", "Contains", "反序列化 - Java Base64 魔术字节"),
    ("aced0005",              "Body", "Contains", "反序列化 - Java Hex 魔术字节"),
    ("O:4:\"",                "Body", "Contains", "反序列化 - PHP 对象"),
    ("a:2:{",                 "Body", "Contains", "反序列化 - PHP 数组"),
    ("__reduce__",            "Body", "Contains", "反序列化 - Python pickle"),
    ("yaml.load",             "Body", "Contains", "反序列化 - YAML unsafe load"),
    ("ObjectInputStream",     "Body", "Contains", "反序列化 - Java ObjectInputStream"),
    ("Runtime.getRuntime",    "Body", "Contains", "反序列化 - Java RCE 链"),

    // ─── 11. Log4Shell / Spring4Shell / 高危 CVE ────────────────────────────────
    ("${jndi:",               "URL",    "Contains", "Log4Shell (CVE-2021-44228)"),
    ("${jndi:",               "Header", "Contains", "Log4Shell - Header 注入"),
    ("${jndi:",               "Body",   "Contains", "Log4Shell - Body 注入"),
    ("${jndi:",               "Cookie", "Contains", "Log4Shell - Cookie 注入"),
    ("${jndi:ldap://",        "URL",    "Contains", "Log4Shell - LDAP 变体"),
    ("${jndi:rmi://",         "URL",    "Contains", "Log4Shell - RMI 变体"),
    ("${jndi:dns://",         "URL",    "Contains", "Log4Shell - DNS 变体"),
    ("${lower:",              "URL",    "Contains", "Log4Shell - 绕过变体 lower"),
    ("${upper:",              "URL",    "Contains", "Log4Shell - 绕过变体 upper"),
    ("${env:",                "URL",    "Contains", "Log4Shell - 环境变量泄露"),
    ("class.module.classLoader", "URL", "Contains", "Spring4Shell (CVE-2022-22965)"),
    ("class.module.classLoader", "Body","Contains", "Spring4Shell - Body 注入"),

    // ─── 12. Prototype Pollution (JavaScript) ──────────────────────────────────
    ("__proto__",             "URL",    "Contains", "Prototype Pollution - __proto__"),
    ("__proto__",             "Body",   "Contains", "Prototype Pollution - Body"),
    ("constructor.prototype", "URL",    "Contains", "Prototype Pollution - constructor"),
    ("constructor.prototype", "Body",   "Contains", "Prototype Pollution - Body constructor"),
    ("constructor[\"prototype\"]", "Body", "Contains", "Prototype Pollution - 方括号语法"),

    // ─── 13. 扫描器 / 恶意 User-Agent ──────────────────────────────────────────
    ("sqlmap",                "User-Agent", "Contains", "扫描器 - sqlmap"),
    ("nikto",                 "User-Agent", "Contains", "扫描器 - Nikto"),
    ("masscan",               "User-Agent", "Contains", "扫描器 - Masscan"),
    ("nessus",                "User-Agent", "Contains", "扫描器 - Nessus"),
    ("nmap",                  "User-Agent", "Contains", "扫描器 - Nmap"),
    ("acunetix",              "User-Agent", "Contains", "扫描器 - Acunetix"),
    ("zgrab",                 "User-Agent", "Contains", "扫描器 - zgrab"),
    ("dirsearch",             "User-Agent", "Contains", "扫描器 - dirsearch"),
    ("gobuster",              "User-Agent", "Contains", "扫描器 - gobuster"),
    ("wfuzz",                 "User-Agent", "Contains", "扫描器 - wfuzz"),
    ("ffuf",                  "User-Agent", "Contains", "扫描器 - ffuf"),
    ("nuclei",                "User-Agent", "Contains", "扫描器 - Nuclei"),
    ("jaeles",                "User-Agent", "Contains", "扫描器 - Jaeles"),
    ("burpsuite",             "User-Agent", "Contains", "扫描器 - BurpSuite"),
    ("openvas",               "User-Agent", "Contains", "扫描器 - OpenVAS"),
    ("w3af",                  "User-Agent", "Contains", "扫描器 - w3af"),
    ("arachni",               "User-Agent", "Contains", "扫描器 - Arachni"),
    ("skipfish",              "User-Agent", "Contains", "扫描器 - Skipfish"),
    ("havij",                 "User-Agent", "Contains", "扫描器 - Havij"),
    ("appscan",               "User-Agent", "Contains", "扫描器 - IBM AppScan"),
    ("webscarab",             "User-Agent", "Contains", "扫描器 - WebScarab"),
    ("htttrack",              "User-Agent", "Contains", "爬虫 - HTTrack"),
    ("python-requests",       "User-Agent", "Contains", "自动化脚本 - Python Requests"),
    ("go-http-client",        "User-Agent", "Contains", "自动化脚本 - Go HTTP Client"),
    ("libwww-perl",           "User-Agent", "Contains", "自动化脚本 - Perl LWP"),
    ("scrapy",                "User-Agent", "Contains", "爬虫 - Scrapy"),
    ("headlesschrome",        "User-Agent", "Contains", "无头浏览器 - Headless Chrome"),
    ("phantomjs",             "User-Agent", "Contains", "无头浏览器 - PhantomJS"),
    ("censys",                "User-Agent", "Contains", "扫描器 - Censys"),
    ("shodan",                "User-Agent", "Contains", "扫描器 - Shodan"),

    // ─── 14. 敏感文件/路径探测 ─────────────────────────────────────────────────
    ("wp-admin",              "URL",  "Contains", "探测 - WordPress 后台"),
    ("wp-login.php",          "URL",  "Contains", "探测 - WordPress 登录"),
    ("wp-content/uploads",    "URL",  "Contains", "探测 - WordPress 上传"),
    ("xmlrpc.php",            "URL",  "Contains", "探测 - WordPress XML-RPC"),
    (".env",                  "URL",  "Contains", "探测 - 环境变量文件"),
    (".git/",                 "URL",  "Contains", "探测 - Git 仓库泄露"),
    (".git/config",           "URL",  "Contains", "探测 - Git 配置"),
    (".git/HEAD",             "URL",  "Contains", "探测 - Git HEAD"),
    ("/.svn/",                "URL",  "Contains", "探测 - SVN 仓库泄露"),
    ("/.hg/",                 "URL",  "Contains", "探测 - Mercurial 仓库"),
    ("/.DS_Store",            "URL",  "Contains", "探测 - macOS DS_Store"),
    ("phpmyadmin",            "URL",  "Contains", "探测 - phpMyAdmin"),
    ("adminer",               "URL",  "Contains", "探测 - Adminer 数据库管理"),
    ("/actuator",             "URL",  "Contains", "探测 - Spring Boot Actuator"),
    ("/actuator/env",         "URL",  "Contains", "探测 - Spring Actuator 环境变量"),
    ("/actuator/heapdump",    "URL",  "Contains", "探测 - Spring Actuator 堆转储"),
    ("/manager/html",         "URL",  "Contains", "探测 - Tomcat Manager"),
    ("/console",              "URL",  "Contains", "探测 - H2/WebLogic Console"),
    ("/druid/",               "URL",  "Contains", "探测 - Druid 监控"),
    ("/swagger-ui",           "URL",  "Contains", "探测 - Swagger API 文档"),
    ("/api-docs",             "URL",  "Contains", "探测 - API 文档"),
    ("/.well-known/",         "URL",  "Contains", "探测 - Well-Known 路径"),
    ("/debug/",               "URL",  "Contains", "探测 - Debug 端点"),
    ("/trace",                "URL",  "Contains", "探测 - Trace 端点"),
    ("/server-status",        "URL",  "Contains", "探测 - Apache Status"),
    ("/server-info",          "URL",  "Contains", "探测 - Apache Info"),
    ("/elmah.axd",            "URL",  "Contains", "探测 - ASP.NET ELMAH 日志"),
    ("/web.config",           "URL",  "Contains", "探测 - IIS 配置"),
    ("/WEB-INF/",             "URL",  "Contains", "探测 - Java WEB-INF"),
    ("/META-INF/",            "URL",  "Contains", "探测 - Java META-INF"),
    ("/config.php",           "URL",  "Contains", "探测 - PHP 配置文件"),
    ("/wp-config.php",        "URL",  "Contains", "探测 - WordPress 配置"),
    ("/database.yml",         "URL",  "Contains", "探测 - Rails 数据库配置"),
    ("/.htaccess",            "URL",  "Contains", "探测 - Apache htaccess"),
    ("/.htpasswd",            "URL",  "Contains", "探测 - Apache htpasswd"),
    ("/backup",               "URL",  "Contains", "探测 - 备份文件"),
    (".bak",                  "URL",  "Contains", "探测 - .bak 备份"),
    (".sql",                  "URL",  "Contains", "探测 - SQL 数据库转储"),
    (".tar.gz",               "URL",  "Contains", "探测 - tar.gz 压缩包"),
    (".zip",                  "URL",  "Contains", "探测 - ZIP 压缩包"),
    ("/dump",                 "URL",  "Contains", "探测 - 数据转储"),

    // ─── 15. Webshell / 后门检测 ───────────────────────────────────────────────
    ("eval($_",               "Body", "Contains", "Webshell - PHP eval 后门"),
    ("assert($_",             "Body", "Contains", "Webshell - PHP assert 后门"),
    ("base64_decode($_",      "Body", "Contains", "Webshell - PHP 编码后门"),
    ("gzinflate(",            "Body", "Contains", "Webshell - PHP 压缩混淆"),
    ("str_rot13(",            "Body", "Contains", "Webshell - PHP ROT13 编码"),
    ("c99shell",              "URL",  "Contains", "Webshell - c99 探测"),
    ("r57shell",              "URL",  "Contains", "Webshell - r57 探测"),
    ("webshell",              "URL",  "Contains", "Webshell - 通用路径探测"),
    (".jsp?cmd=",             "URL",  "Contains", "Webshell - JSP 命令后门"),
    (".asp?cmd=",             "URL",  "Contains", "Webshell - ASP 命令后门"),

    // ─── 16. Header 层攻击 ─────────────────────────────────────────────────────
    ("x-forwarded-for: 127",  "Header", "Contains", "Header 伪造 - XFF 回环"),
    ("x-forwarded-for: 10.",  "Header", "Contains", "Header 伪造 - XFF 内网"),
    ("x-forwarded-for: 192.168", "Header", "Contains", "Header 伪造 - XFF 内网"),
    ("proxy: http://",        "Header", "Contains", "Header 注入 - httpoxy"),

    // ─── 17. 正则规则（高级检测）────────────────────────────────────────────────
    // 17.1 SQLi 正则（覆盖变体绕过）
    ("(?i)(union\\s+(all\\s+)?select)", "URL",  "Regex", "SQLi Regex - UNION SELECT 模糊匹配"),
    ("(?i)(select\\s+.*\\s+from\\s+)", "URL",   "Regex", "SQLi Regex - SELECT FROM 模式"),
    ("(?i)(insert\\s+into\\s+)",      "URL",   "Regex", "SQLi Regex - INSERT INTO 模式"),
    ("(?i)(delete\\s+from\\s+)",      "URL",   "Regex", "SQLi Regex - DELETE FROM 模式"),
    ("(?i)(update\\s+\\w+\\s+set\\s+)", "URL", "Regex", "SQLi Regex - UPDATE SET 模式"),
    ("(?i)(or\\s+\\d+\\s*=\\s*\\d+)", "URL",   "Regex", "SQLi Regex - OR 数字比较"),
    ("(?i)(and\\s+\\d+\\s*=\\s*\\d+)", "URL",  "Regex", "SQLi Regex - AND 数字比较"),
    ("(?i)(sleep\\s*\\(\\s*\\d+\\s*\\))", "URL", "Regex", "SQLi Regex - sleep() 盲注"),
    ("(?i)(benchmark\\s*\\()", "URL", "Regex", "SQLi Regex - benchmark() 盲注"),
    ("(?i)('\\s*(or|and)\\s+')", "URL", "Regex", "SQLi Regex - 引号逻辑注入"),

    // 17.2 XSS 正则
    ("(?i)(<\\s*script[^>]*>)",  "URL",  "Regex", "XSS Regex - script 标签变体"),
    ("(?i)(<\\s*script[^>]*>)",  "Body", "Regex", "XSS Regex - Body script 变体"),
    ("(?i)(on\\w+=\\s*[\"'])",   "URL",  "Regex", "XSS Regex - 事件处理器"),
    ("(?i)(on\\w+=\\s*[\"'])",   "Body", "Regex", "XSS Regex - Body 事件处理器"),
    ("(?i)(javascript\\s*:)",    "URL",  "Regex", "XSS Regex - javascript: 变体"),
    ("(?i)(<\\s*(iframe|object|embed|svg|math))", "URL", "Regex", "XSS Regex - 危险标签"),

    // 17.3 路径穿越正则
    ("(\\.\\./){2,}",            "URL",  "Regex", "路径穿越 Regex - 多层穿越"),
    ("(%2e){2}(%2f|%5c)",        "URL",  "Regex", "路径穿越 Regex - 编码穿越"),

    // 17.4 命令注入正则
    ("(?i)(;\\s*(ls|cat|id|whoami|uname|pwd|wget|curl))", "URL", "Regex", "RCE Regex - 分号命令链"),
    ("(?i)(\\|\\s*(ls|cat|id|whoami|uname|pwd))",         "URL", "Regex", "RCE Regex - 管道命令链"),
    ("(?i)(\\$\\(\\s*(id|whoami|uname|cat))",             "URL", "Regex", "RCE Regex - 子命令执行"),

    // 17.5 Log4Shell 正则（覆盖混淆变体）
    ("(?i)(\\$\\{[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:)", "URL",    "Regex", "Log4Shell Regex - JNDI 混淆绕过"),
    ("(?i)(\\$\\{[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:)", "Header", "Regex", "Log4Shell Regex - Header JNDI 混淆"),
    ("(?i)(\\$\\{[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:)", "Body",   "Regex", "Log4Shell Regex - Body JNDI 混淆"),
    ("(?i)(\\$\\{[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:)", "Cookie", "Regex", "Log4Shell Regex - Cookie JNDI 混淆"),

    // 17.6 SSTI 正则
    ("(\\{\\{.*\\}\\})",    "URL",  "Regex", "SSTI Regex - 双花括号表达式"),
    ("(\\{\\{.*\\}\\})",    "Body", "Regex", "SSTI Regex - Body 双花括号"),
    ("(\\$\\{.*\\})",       "Body", "Regex", "SSTI Regex - Body 美元表达式"),
];
