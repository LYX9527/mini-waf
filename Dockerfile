# ==========================================
# 1. 前端构建阶段 (保持使用稳定的 Node 20)
# ==========================================
FROM node:20-slim AS frontend-builder
WORKDIR /app

# 优化：先复制 package.json，利用 Docker 缓存层加速依赖安装
COPY admin_frontend/package.json admin_frontend/package-lock.json* ./
# 优化：使用 npm ci 替代 npm install (如果存在 lock 文件)，构建更稳定快速
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# 复制前端源码并构建
COPY admin_frontend/ ./
RUN npm run build


# ==========================================
# 2. 后端构建阶段 (Rust 编译)
# ==========================================
# ⭐ 核心修复：将 rust 版本升级到 latest (或指定 1.80+)，以支持 edition="2024"
# 如果你已经把 Cargo.toml 改成了 edition="2021"，这里保持 1.76 也可以，但升级总是没坏处
FROM rust:latest AS backend-builder
WORKDIR /app

# 安装编译所需的依赖
RUN apt-get update && apt-get install -y pkg-config libssl-dev wget ca-certificates && rm -rf /var/lib/apt/lists/*

# 复制全部源码
COPY . .

# 设置 SQLx 离线模式
ENV SQLX_OFFLINE=true

# 编译出 Release 版本二进制文件
RUN cargo build --release

# 下载预建的 GeoLite 数据库
# 注意：你的原链接中的日期 "2026.04.13" 可能失效，我替换成了 "latest" 以确保总能下到
RUN mkdir -p /app/data && \
    wget -qO /app/data/GeoLite2-City.mmdb "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb" && \
    wget -qO /app/data/GeoLite2-Country.mmdb "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"


# ==========================================
# 3. 最终运行阶段 (极简运行环境)
# ==========================================
FROM debian:bookworm-slim
WORKDIR /opt/mini_waf

# 安装运行时的必要库
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

# 从后端提取可执行文件
COPY --from=backend-builder /app/target/release/mini_waf /usr/local/bin/mini_waf

# 从后端提取资源文件 (如果有 migrations 文件夹的话)
# 注意：如果项目中没有 migrations 文件夹，这一行会报错。
# 建议在项目中创建一个空的 migrations 文件夹，或者如果不用 SQLx 迁移，把这行注释掉。
COPY --from=backend-builder /app/migrations ./migrations

# 复制环境变量文件和数据库
COPY --from=backend-builder /app/data ./data

# 从前端提取构建好的静态资源
COPY --from=frontend-builder /app/dist ./admin_frontend/dist

# 声明暴露的端口 (48080: WAF 代理, 8081: 管理后台)
EXPOSE 48080 8081

# 设置日志级别
ENV RUST_LOG=info

# 启动 WAF 网关
CMD ["mini_waf"]