#!/bin/bash
set -e

# ============================================================
# Mini-WAF 一键安装脚本
# 项目地址: https://github.com/LYX9527/mini-waf
# ============================================================

INSTALL_DIR="/opt/mini-waf"
COMPOSE_URL="https://raw.githubusercontent.com/LYX9527/mini-waf/master/docker/docker-compose.yml"

# -------- 颜色输出 --------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# -------- 检查依赖 --------
check_deps() {
    info "检查运行环境..."
    command -v docker  >/dev/null 2>&1 || error "未检测到 Docker，请先安装 Docker: https://docs.docker.com/get-docker/"
    command -v curl    >/dev/null 2>&1 || error "未检测到 curl，请先安装 curl"

    # 检查 compose 插件或独立命令
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        error "未检测到 Docker Compose，请先安装: https://docs.docker.com/compose/install/"
    fi

    success "依赖检查通过 (Compose: $COMPOSE_CMD)"
}

# -------- 检查是否已安装 --------
check_existing() {
    if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
        warn "检测到 $INSTALL_DIR 已存在安装文件。"
        read -rp "是否覆盖重新安装？(y/N): " answer
        case "$answer" in
            y|Y) info "继续安装..." ;;
            *)   info "已取消安装。"; exit 0 ;;
        esac
    fi
}

# -------- 创建安装目录 --------
prepare_dir() {
    info "创建安装目录 $INSTALL_DIR ..."
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    success "目录准备完成"
}

# -------- 下载 docker-compose.yml --------
download_compose() {
    info "下载 docker-compose.yml ..."
    curl -sSL -o docker-compose.yml "$COMPOSE_URL" || error "下载失败，请检查网络连接或访问 $COMPOSE_URL"
    success "docker-compose.yml 下载完成"
}

# -------- 生成随机安全密钥 --------
gen_secret() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "$1" | head -n 1
}

# -------- 生成 .env 配置文件 --------
generate_env() {
    info "生成安全随机密钥..."

    JWT_SECRET=$(gen_secret 32)
    DB_ROOT_PASSWORD=$(gen_secret 24)
    DB_PASSWORD=$(gen_secret 24)

    # 询问端口配置（回车使用默认值）
    echo ""
    echo -e "${BOLD}端口配置（直接回车使用默认值）${NC}"
    read -rp "  WAF 代理端口       [默认: 49888]: " WAF_PORT
    WAF_PORT="${WAF_PORT:-49888}"
    read -rp "  管理控制台端口     [默认: 49777]: " ADMIN_PORT
    ADMIN_PORT="${ADMIN_PORT:-49777}"

    cat > .env <<EOF
# Mini-WAF 环境配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

WAF_PORT=${WAF_PORT}
ADMIN_PORT=${ADMIN_PORT}

# JWT 签名密钥 (请勿泄露)
JWT_SECRET=${JWT_SECRET}

# MySQL 数据库配置
DB_ROOT_PASSWORD=${DB_ROOT_PASSWORD}
DB_USER=mini_waf_user
DB_PASSWORD=${DB_PASSWORD}
DB_NAME=mini_waf
EOF

    # 将 .env 中的密码写入 docker-compose.yml 的环境变量
    sed -i.bak \
        -e "s|49888:48080|${WAF_PORT}:48080|g" \
        -e "s|49777:8081|${ADMIN_PORT}:8081|g" \
        -e "s|mysql://mini_waf_user:password@mysql:3306/mini_waf?timezone=Asia%2FShanghai|mysql://mini_waf_user:${DB_PASSWORD}@mysql:3306/mini_waf?timezone=Asia%2FShanghai|g" \
        -e "s|super_secret_waf_key_please_change|${JWT_SECRET}|g" \
        -e "s|MYSQL_ROOT_PASSWORD=rootpassword|MYSQL_ROOT_PASSWORD=${DB_ROOT_PASSWORD}|g" \
        -e "s|MYSQL_PASSWORD=password|MYSQL_PASSWORD=${DB_PASSWORD}|g" \
        docker-compose.yml
    rm -f docker-compose.yml.bak

    success "配置文件生成完成"
}

# -------- 启动服务 --------
start_services() {
    info "拉取镜像并启动服务（首次运行可能需要数分钟）..."
    $COMPOSE_CMD up -d || error "服务启动失败，请检查 Docker 日志: $COMPOSE_CMD logs"
    success "所有服务已启动"
}

# -------- 等待服务就绪 --------
wait_ready() {
    info "等待 WAF 服务就绪..."
    local MAX=30
    local i=0
    while ! curl -sf "http://127.0.0.1:${ADMIN_PORT}/api/v1/auth/check-init" >/dev/null 2>&1; do
        sleep 2
        i=$((i+1))
        if [ $i -ge $MAX ]; then
            warn "服务启动超时，请手动检查: $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml logs"
            return
        fi
        echo -n "."
    done
    echo ""
    success "WAF 服务就绪"
}

# -------- 获取公网 IP --------
get_public_ip() {
    curl -s --max-time 5 ifconfig.me 2>/dev/null \
        || curl -s --max-time 5 icanhazip.com 2>/dev/null \
        || echo "<YOUR_SERVER_IP>"
}

# -------- 打印安装结果 --------
print_summary() {
    PUBLIC_IP=$(get_public_ip)
    echo ""
    echo -e "${BOLD}=============================================${NC}"
    echo -e "${GREEN}  Mini-WAF 安装成功！${NC}"
    echo -e "${BOLD}=============================================${NC}"
    echo ""
    echo -e "  WAF 代理地址:      ${CYAN}http://${PUBLIC_IP}:${WAF_PORT}${NC}"
    echo -e "  管理控制台:        ${CYAN}http://${PUBLIC_IP}:${ADMIN_PORT}${NC}"
    echo ""
    echo -e "  安装目录:          $INSTALL_DIR"
    echo -e "  配置文件:          $INSTALL_DIR/.env"
    echo ""
    echo -e "${BOLD}后续操作:${NC}"
    echo "  1. 访问管理控制台，完成首次初始化（设置管理员账号）"
    echo "  2. 在「站点管理」中添加路由规则，将流量代理到内部服务"
    echo "  3. 在「Nginx 管理」中为各域名配置反向代理，使外部流量进入 WAF"
    echo ""
    echo -e "${BOLD}常用命令:${NC}"
    echo "  查看日志:   $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml logs -f"
    echo "  停止服务:   $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml down"
    echo "  重启服务:   $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml restart"
    echo ""
    echo -e "  更多信息: ${CYAN}https://github.com/LYX9527/mini-waf${NC}"
    echo -e "${BOLD}=============================================${NC}"
}

# -------- 主流程 --------
main() {
    echo ""
    echo -e "${BOLD}=============================================${NC}"
    echo -e "       Mini-WAF 一键安装脚本"
    echo -e "  https://github.com/LYX9527/mini-waf"
    echo -e "${BOLD}=============================================${NC}"
    echo ""

    check_deps
    check_existing
    prepare_dir
    download_compose
    generate_env
    start_services
    wait_ready
    print_summary
}

main "$@"