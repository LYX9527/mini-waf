# 1. 前端构建阶段
FROM node:20-slim AS frontend-builder
WORKDIR /app
COPY admin_frontend/package.json ./
# 安装依赖并构建
RUN npm install
COPY admin_frontend/ ./
RUN npm run build

# 2. 后端构建阶段
FROM rust:1.76-slim AS backend-builder
WORKDIR /app
# 安装编译所需的依赖
RUN apt-get update && apt-get install -y pkg-config libssl-dev wget ca-certificates
# 复制全部源码并编译
COPY . .
RUN cargo build --release

# 下载预建的 GeoLite 数据库
RUN mkdir -p /app/data && \
    wget -qO /app/data/GeoLite2-City.mmdb https://github.com/P3TERX/GeoLite.mmdb/releases/download/2026.04.13/GeoLite2-City.mmdb && \
    wget -qO /app/data/GeoLite2-Country.mmdb https://github.com/P3TERX/GeoLite.mmdb/releases/download/2026.04.13/GeoLite2-Country.mmdb

# 3. 最终运行镜像
FROM debian:bookworm-slim
WORKDIR /opt/mini_waf

# 安装运行时的必要库（如 openssl, ca-certificates）
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

# 从后端构建产物中提取可执行二进制
COPY --from=backend-builder /app/target/release/mini_waf /usr/local/bin/mini_waf
# 复制迁移脚本、默认数据等资源
COPY --from=backend-builder /app/migrations ./migrations
COPY --from=backend-builder /app/.env ./
COPY --from=backend-builder /app/data ./data

# 从前端构建产物中提取静态资源
COPY --from=frontend-builder /app/dist ./admin_frontend/dist

# 声明暴露的端口
EXPOSE 48080 8081

# 设置运行环境
ENV RUST_LOG=info

# 启动 WAF
CMD ["mini_waf"]
