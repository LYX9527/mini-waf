<div align="center">

<img src="./install/banner.png" width="840"/>

**轻量级高性能 Web 应用防火墙**

[![Build](https://img.shields.io/github/actions/workflow/status/LYX9527/mini-waf/build.yml?style=flat-square&logo=github&label=Build)](https://github.com/LYX9527/mini-waf/actions)
[![Image](https://img.shields.io/badge/ghcr.io-mini--waf-00f0ff?style=flat-square&logo=docker)](https://ghcr.io/lyx9527/mini-waf)
[![License](https://img.shields.io/github/license/LYX9527/mini-waf?style=flat-square&color=7000ff)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)

*基于 Rust + Tokio + Hyper 构建 · 域名路由 · 攻击拦截 · Docker 一键部署*

</div>

---

## 架构概览

```
                        ┌─────────────────────────────────────────┐
  Internet              │            Mini-WAF 处理链路              │
                        │                                          │
  ┌──────┐  :49888      │  ┌──────────┐  ┌─────────┐  ┌────────┐ │    ┌─────────────┐
  │ 用户 │ ──────────▶  │  │ IP 过滤  │─▶│ 规则引擎 │─▶│ 路由   │ │──▶ │ 后端服务 A  │
  └──────┘              │  │ 黑白名单  │  │SQLi/XSS │  │域名+路径│ │    └─────────────┘
                        │  │ 国家阻断  │  │ 正则匹配 │  │ 精准匹配 │ │    ┌─────────────┐
  ┌──────┐  :49777      │  └──────────┘  └─────────┘  └────────┘ │──▶ │ 后端服务 B  │
  │ 管理 │ ──────────▶  │                  管理控制台               │    └─────────────┘
  └──────┘              └─────────────────────────────────────────┘
```

## 核心特性

| 模块 | 能力 |
|------|------|
| **反向代理** | 域名 + 路径前缀双维度路由，同端口保护多个域名 |
| **攻击拦截** | 内置 SQL 注入、XSS、目录穿越规则，支持自定义正则热重载 |
| **IP 管控** | 黑白名单、GeoIP 国家级封锁，O(1) 内存匹配 |
| **限流熔断** | 滑动窗口限速 + 惩罚分机制，自动封禁异常 IP |
| **Nginx 管理** | 可视化编辑配置，保存后自动 reload，无需 SSH |
| **实时监控** | 访问日志、攻击日志、QPS 大盘、地理位置溯源 |
| **负载均衡** | Round-Robin 轮询多上游节点，自动健康检查剔除 |

## 快速部署

### 一键安装（推荐）

```bash
bash <(curl -sSL https://raw.githubusercontent.com/LYX9527/mini-waf/master/install/install.sh)
```

> 需要已安装 Docker 和 Docker Compose。脚本会自动生成随机密钥、配置端口、启动全部服务。

### 手动部署

```bash
# 1. 下载配置文件
mkdir -p /opt/mini-waf && cd /opt/mini-waf
curl -sSL -o docker-compose.yml \
  https://raw.githubusercontent.com/LYX9527/mini-waf/master/docker/docker-compose.yml

# 2. 修改密码（强烈建议）
#    编辑 docker-compose.yml 中的数据库密码和 JWT_SECRET

# 3. 启动
docker compose up -d
```

安装完成后访问管理控制台：`http://<服务器IP>:49777`

## 端口说明

| 端口 | 容器内端口 | 用途 |
|------|-----------|------|
| `49888` | `48080` | WAF 代理入口，所有保护流量从此进入 |
| `49777` | `8081` | 管理控制台，**建议通过防火墙限制访问** |

## 使用指南

### 1. 添加路由规则

在管理控制台 → **站点管理** 中添加路由条目：

| 字段 | 示例 | 说明 |
|------|------|------|
| 路径前缀 | `/` 或 `/api` | 请求路径匹配前缀 |
| 域名限制 | `api.example.com` 或 `*.example.com` | 可选，不填则匹配所有域名 |
| 目标地址 | `127.0.0.1:3000` | 内网服务地址 (host:port) |

**多域名路由示例：**

```
api.example.com  /     →  127.0.0.1:3000   # API 服务
web.example.com  /     →  127.0.0.1:8080   # 前端服务
(任意域名)       /admin →  127.0.0.1:9090   # 通配路由
```

### 2. 接入外部流量

推荐通过 Nginx 将公网 80/443 流量转入 WAF：

```nginx
# 在管理控制台 → Nginx 管理 中添加此配置
server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass         http://mini-waf:48080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    }
}
```

保存后 WAF 会自动下发配置并 reload Nginx，无需 SSH 操作。

### 3. 安全规则

管理控制台 → **安全规则** 支持：

- 内置规则：SQL 注入、XSS、目录穿越
- 自定义关键字匹配（包含/精确/正则三种模式）
- 匹配目标：URL、请求头、请求体、User-Agent
- 热重载：添加规则立即生效，无需重启

## 项目结构

```
mini-waf/
├── src/
│   ├── main.rs              # 入口：初始化状态、加载规则、启动监听
│   ├── state.rs             # 全局共享状态（路由表、规则、计数器）
│   ├── proxy/
│   │   ├── handler.rs       # 请求处理主链路（五阶段过滤）
│   │   ├── router.rs        # 路由匹配（Host + 路径前缀，优先级排序）
│   │   └── response.rs      # 统一响应构建（错误页、重定向）
│   └── api/
│       ├── routes.rs        # 站点路由 CRUD API
│       ├── nginx.rs         # Nginx 配置管理 API
│       ├── logs.rs          # 日志查询 API
│       └── ...
├── admin_frontend/          # React + Ant Design 管理控制台
├── migrations/              # sqlx 数据库迁移文件
├── docker/
│   └── docker-compose.yml   # 完整编排：WAF + Nginx + MySQL
├── install/
│   └── install.sh           # 一键安装脚本
└── site/                    # 项目主页
```

## 技术栈

```
后端                          前端
─────────────────────         ──────────────────────
Rust (1.75+)                  React 18
  ├─ Tokio     (异步运行时)     ├─ Ant Design 5
  ├─ Hyper     (HTTP 协议栈)   ├─ TypeScript
  ├─ Axum      (管理 API)      └─ Vite
  ├─ sqlx      (MySQL 驱动)
  ├─ moka      (内存缓存)      基础设施
  ├─ maxminddb (GeoIP)        ──────────────────────
  └─ regex     (规则引擎)      Docker + Docker Compose
                               MySQL 8.0
                               Nginx Alpine
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DATABASE_URL` | — | MySQL 连接字符串 |
| `JWT_SECRET` | — | JWT 签名密钥（**必须修改**） |
| `RUST_LOG` | `info` | 日志级别 (error/warn/info/debug) |
| `TZ` | `Asia/Shanghai` | 容器时区 |
| `MMDB_PATH` | `./data/GeoLite2-City.mmdb` | GeoIP 数据库路径（可选）|

## GeoIP 支持（可选）

下载 GeoLite2-City.mmdb 并挂载到容器，即可启用国家/城市归属地查询和国家封锁功能：

```bash
# 下载（需要 MaxMind 免费账号）
# https://www.maxmind.com/en/geolite2/signup

mkdir -p /opt/mini-waf/data
cp GeoLite2-City.mmdb /opt/mini-waf/data/
docker compose restart mini-waf
```

## 常见问题

**Q: 如何只允许特定 IP 访问管理控制台？**

```bash
# UFW 示例：只允许 1.2.3.4 访问 49777
ufw allow from 1.2.3.4 to any port 49777
ufw deny 49777
```

**Q: 如何通过 SSH 隧道安全访问控制台？**

```bash
ssh -L 18080:127.0.0.1:49777 user@your-server
# 然后访问 http://localhost:18080
```

**Q: 如何更新到最新版本？**

```bash
cd /opt/mini-waf
docker compose pull
docker compose up -d
```

**Q: Nginx 管理提示无法连接 Docker Socket？**

确认 `docker-compose.yml` 中 mini-waf 服务已挂载：
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

## 开发构建

```bash
# 后端
cargo sqlx prepare   # 更新 sqlx 查询缓存（需要本地 MySQL）
cargo build --release

# 前端
cd admin_frontend
npm install
npm run build        # 构建产物输出到 dist/

# Docker 镜像
docker build -t mini-waf .
```

## License

[MIT](LICENSE) · 由 Rust 社区工具链强力驱动

---

<div align="center">

[主页](https://lyx9527.github.io/mini-waf) · [GitHub](https://github.com/LYX9527/mini-waf) · [问题反馈](https://github.com/LYX9527/mini-waf/issues)

</div>
