#!/bin/bash
#
# VPS 一键初始化脚本
# 基于科技lion脚本核心命令，非交互式自动化
#
# 使用方法：
#   wget -qO- https://raw.githubusercontent.com/shuggg999/vps-scripts/main/vps-init.sh | bash
#
# ============================================================

# ==================== 自动获取配置 ====================
# HOSTNAME: 自动读取当前主机名
# SSH_PUBKEY: 自动从 GitHub 获取
GITHUB_USER="shuggg999"

# ==================== 可选修改 ====================
SSH_PORT=2222                      # SSH 端口（与重装脚本一致）
TIMEZONE="Asia/Shanghai"           # 时区
# SWAP_SIZE 留空则自动计算，或指定具体值如: SWAP_SIZE=2048 (单位MB)
SWAP_SIZE=""

# ==================== 以下无需修改 ====================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# 工具函数
# ============================================================

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

# 检查是否为 root
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "请使用 root 用户运行此脚本"
        exit 1
    fi
}

# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "无法检测系统类型"
        exit 1
    fi

    case "$OS" in
        debian|ubuntu)
            PKG_MANAGER="apt"
            PKG_UPDATE="apt update && apt upgrade -y"
            PKG_INSTALL="apt install -y"
            PKG_CLEAN="apt autoremove -y && apt autoclean"
            ;;
        centos|rhel|rocky|almalinux)
            PKG_MANAGER="yum"
            PKG_UPDATE="yum update -y"
            PKG_INSTALL="yum install -y"
            PKG_CLEAN="yum autoremove -y && yum clean all"
            ;;
        fedora)
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf update -y"
            PKG_INSTALL="dnf install -y"
            PKG_CLEAN="dnf autoremove -y && dnf clean all"
            ;;
        *)
            log_error "不支持的系统: $OS"
            exit 1
            ;;
    esac

    log_info "检测到系统: $OS $OS_VERSION"
    log_info "包管理器: $PKG_MANAGER"
}

# 检测是否为国内服务器
detect_location() {
    local country=$(curl -s --max-time 3 ipinfo.io/country 2>/dev/null || echo "unknown")

    if [ "$country" = "CN" ]; then
        IS_CHINA=true
        log_info "检测到国内服务器 (CN)"
    else
        IS_CHINA=false
        log_info "检测到海外服务器 ($country)"
    fi
}

# 自动计算 SWAP 大小
calc_swap_size() {
    if [ -n "$SWAP_SIZE" ]; then
        log_info "使用指定的 SWAP 大小: ${SWAP_SIZE}MB"
        return
    fi

    local mem_total=$(free -m | awk '/^Mem:/{print $2}')

    if [ "$mem_total" -le 1024 ]; then
        SWAP_SIZE=1024
    elif [ "$mem_total" -le 2048 ]; then
        SWAP_SIZE=2048
    else
        SWAP_SIZE=4096
    fi

    log_info "物理内存: ${mem_total}MB，自动设置 SWAP: ${SWAP_SIZE}MB"
}

# ============================================================
# 主要功能函数（后续逐步添加）
# ============================================================

# 1. 系统更新
do_system_update() {
    log_step "1. 系统更新"

    log_info "正在更新系统..."
    eval $PKG_UPDATE

    if [ $? -eq 0 ]; then
        log_success "系统更新完成"
    else
        log_error "系统更新失败"
        return 1
    fi
}

# 2. 系统清理
do_system_clean() {
    log_step "2. 系统清理"

    log_info "正在清理系统..."
    eval $PKG_CLEAN

    # 清理日志
    journalctl --vacuum-time=7d 2>/dev/null

    # 清理临时文件
    rm -rf /tmp/* 2>/dev/null

    log_success "系统清理完成"
}

# 3. 切换更新源（自动判断国内/国外）
do_switch_mirror() {
    log_step "3. 切换更新源"

    if [ "$OS" != "debian" ] && [ "$OS" != "ubuntu" ]; then
        log_warn "仅支持 Debian/Ubuntu 自动切换源，跳过"
        return 0
    fi

    # 备份原有源
    cp /etc/apt/sources.list /etc/apt/sources.list.bak 2>/dev/null

    if [ "$IS_CHINA" = true ]; then
        log_info "切换到国内镜像源（阿里云）..."
        if [ "$OS" = "debian" ]; then
            cat > /etc/apt/sources.list << 'EOF'
deb https://mirrors.aliyun.com/debian/ bookworm main contrib non-free non-free-firmware
deb https://mirrors.aliyun.com/debian/ bookworm-updates main contrib non-free non-free-firmware
deb https://mirrors.aliyun.com/debian/ bookworm-backports main contrib non-free non-free-firmware
deb https://mirrors.aliyun.com/debian-security bookworm-security main contrib non-free non-free-firmware
EOF
        elif [ "$OS" = "ubuntu" ]; then
            cat > /etc/apt/sources.list << 'EOF'
deb https://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse
deb https://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse
EOF
        fi
    else
        log_info "使用官方源（海外服务器）..."
        # 海外服务器使用默认源即可，不修改
    fi

    apt update
    log_success "更新源切换完成"
}

# 4. BBR3 加速
do_bbr3() {
    log_step "4. BBR3 加速"

    # 检查当前 BBR 状态
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    log_info "当前拥塞控制算法: $current_cc"

    # 检查是否已启用 BBR
    if [ "$current_cc" = "bbr" ]; then
        log_success "BBR 已启用"
        return 0
    fi

    # 启用 BBR
    log_info "正在启用 BBR..."

    # 加载 BBR 模块
    modprobe tcp_bbr 2>/dev/null

    # 写入配置
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf

    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

    # 应用配置
    sysctl -p

    # 验证
    local new_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [ "$new_cc" = "bbr" ]; then
        log_success "BBR 启用成功"
    else
        log_warn "BBR 启用可能需要重启生效"
    fi
}

# 5. 内核参数优化（kejilion optimize_high_performance 完整版）
do_kernel_optimize() {
    log_step "5. 内核参数优化"

    log_info "正在优化内核参数..."

    # 1. 优化文件描述符（kejilion）
    log_info "优化文件描述符..."
    ulimit -n 65535

    # 持久化文件描述符限制
    cat > /etc/security/limits.d/99-nofile.conf << 'EOF'
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

    # 2. 创建 sysctl 优化配置文件
    log_info "优化虚拟内存和网络..."
    cat > /etc/sysctl.d/99-vps-optimize.conf << 'EOF'
# 内存优化（kejilion optimize_high_performance）
vm.swappiness=10
vm.dirty_ratio=15
vm.dirty_background_ratio=5
vm.overcommit_memory=1
vm.min_free_kbytes=65536
vm.vfs_cache_pressure=50

# 网络优化（kejilion optimize_high_performance）
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.netdev_max_backlog=250000
net.core.somaxconn=4096

# TCP 优化（kejilion optimize_high_performance）
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1

# 连接优化
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=10
net.ipv4.tcp_fin_timeout=30

# CPU 优化（kejilion optimize_high_performance）
kernel.sched_autogroup_enabled=0
kernel.numa_balancing=0

# 安全优化
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
EOF

    # 3. 禁用透明大页面（kejilion optimize_high_performance）
    log_info "禁用透明大页面..."
    if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
        echo never > /sys/kernel/mm/transparent_hugepage/enabled
    fi

    # 持久化透明大页面设置
    if [ -d /etc/rc.local.d ]; then
        echo 'echo never > /sys/kernel/mm/transparent_hugepage/enabled' >> /etc/rc.local
    fi

    # 4. 应用配置
    sysctl --system > /dev/null 2>&1

    log_success "内核参数优化完成"
}

# 6. DNS 优化（kejilion set_dns 完整版，支持 IPv4 + IPv6）
do_dns_optimize() {
    log_step "6. DNS 优化"

    log_info "正在优化 DNS..."

    # 检测 IPv4 和 IPv6 地址
    local ipv4_address=$(curl -s --max-time 3 ipv4.ip.sb 2>/dev/null)
    local ipv6_address=$(curl -s --max-time 3 ipv6.ip.sb 2>/dev/null)

    # 解除 resolv.conf 锁定
    chattr -i /etc/resolv.conf 2>/dev/null

    # 备份
    cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null

    # 清空并写入新 DNS
    > /etc/resolv.conf

    if [ "$IS_CHINA" = true ]; then
        log_info "使用国内 DNS..."
        # IPv4 DNS（kejilion: 223.5.5.5 183.60.83.19）
        if [ -n "$ipv4_address" ]; then
            echo "nameserver 223.5.5.5" >> /etc/resolv.conf
            echo "nameserver 183.60.83.19" >> /etc/resolv.conf
        fi
        # IPv6 DNS（kejilion: 2400:3200::1 2400:da00::6666）
        if [ -n "$ipv6_address" ]; then
            echo "nameserver 2400:3200::1" >> /etc/resolv.conf
            echo "nameserver 2400:da00::6666" >> /etc/resolv.conf
        fi
    else
        log_info "使用国外 DNS..."
        # IPv4 DNS（kejilion: 1.1.1.1 8.8.8.8）
        if [ -n "$ipv4_address" ]; then
            echo "nameserver 1.1.1.1" >> /etc/resolv.conf
            echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        fi
        # IPv6 DNS（kejilion: 2606:4700:4700::1111 2001:4860:4860::8888）
        if [ -n "$ipv6_address" ]; then
            echo "nameserver 2606:4700:4700::1111" >> /etc/resolv.conf
            echo "nameserver 2001:4860:4860::8888" >> /etc/resolv.conf
        fi
    fi

    # 如果 resolv.conf 为空，使用默认 DNS（kejilion 逻辑）
    if [ ! -s /etc/resolv.conf ]; then
        echo "nameserver 223.5.5.5" >> /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    fi

    # 锁定 resolv.conf 防止被覆盖
    chattr +i /etc/resolv.conf

    log_success "DNS 优化完成"
}

# 7. IPv4 优先
do_ipv4_priority() {
    log_step "7. 设置 IPv4 优先"

    log_info "正在设置 IPv4 优先..."

    # 修改 gai.conf
    if [ -f /etc/gai.conf ]; then
        sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf
    fi

    # 确保配置存在
    if ! grep -q "precedence ::ffff:0:0/96  100" /etc/gai.conf 2>/dev/null; then
        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
    fi

    log_success "IPv4 优先设置完成"
}

# 8. 虚拟内存设置（kejilion add_swap 函数）
do_swap_setup() {
    log_step "8. 虚拟内存设置"

    log_info "正在设置虚拟内存 ${SWAP_SIZE}MB..."

    # 获取当前系统中所有的 swap 分区
    local swap_partitions=$(grep -E '^/dev/' /proc/swaps | awk '{print $1}')

    # 遍历并删除所有的 swap 分区
    for partition in $swap_partitions; do
        swapoff "$partition" 2>/dev/null
        wipefs -a "$partition" 2>/dev/null
        mkswap -f "$partition" 2>/dev/null
    done

    # 确保 /swapfile 不再被使用
    swapoff /swapfile 2>/dev/null

    # 删除旧的 /swapfile
    rm -f /swapfile

    # 创建新的 swap 分区
    fallocate -l ${SWAP_SIZE}M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    # 写入 fstab
    sed -i '/\/swapfile/d' /etc/fstab
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab

    # Alpine 特殊处理
    if [ -f /etc/alpine-release ]; then
        echo "nohup swapon /swapfile" > /etc/local.d/swap.start
        chmod +x /etc/local.d/swap.start
        rc-update add local
    fi

    log_success "虚拟内存设置完成: ${SWAP_SIZE}MB"
}

# 9. 时区设置（kejilion set_timedate 函数）
do_timezone_setup() {
    log_step "9. 时区设置"

    log_info "正在设置时区: $TIMEZONE..."

    if grep -q 'Alpine' /etc/issue 2>/dev/null; then
        $PKG_INSTALL tzdata
        cp /usr/share/zoneinfo/${TIMEZONE} /etc/localtime
        hwclock --systohc
    else
        timedatectl set-timezone ${TIMEZONE}
    fi

    log_success "时区设置完成: $TIMEZONE"
}

# 10. 主机名修改
do_hostname_setup() {
    log_step "10. 主机名修改"

    log_info "正在设置主机名: $HOSTNAME..."

    hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || hostname "$HOSTNAME"

    # 更新 /etc/hosts
    sed -i "s/127.0.1.1.*/127.0.1.1\t$HOSTNAME/g" /etc/hosts 2>/dev/null
    if ! grep -q "127.0.1.1" /etc/hosts; then
        echo "127.0.1.1	$HOSTNAME" >> /etc/hosts
    fi

    log_success "主机名设置完成: $HOSTNAME"
}

# 11. SSH 端口修改（kejilion new_ssh_port 函数）
do_ssh_port() {
    log_step "11. SSH 端口修改"

    log_info "正在修改 SSH 端口为: $SSH_PORT..."

    # 备份 SSH 配置文件
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # 修改端口
    sed -i 's/^\s*#\?\s*Port/Port/' /etc/ssh/sshd_config
    sed -i "s/Port [0-9]\+/Port $SSH_PORT/g" /etc/ssh/sshd_config

    # 清理额外配置
    rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/* 2>/dev/null

    # 重启 SSH
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service sshd restart 2>/dev/null

    log_success "SSH 端口修改完成: $SSH_PORT"
    log_warn "请记住新端口，下次连接使用: ssh -p $SSH_PORT root@<IP>"
}

# 12. SSH 密钥登录
do_ssh_key() {
    log_step "12. SSH 密钥登录"

    if [ -z "$SSH_PUBKEY" ]; then
        log_warn "SSH_PUBKEY 未设置，跳过"
        return 0
    fi

    log_info "正在配置 SSH 密钥登录..."

    # 创建目录和设置权限（kejilion add_sshkey 函数）
    chmod 700 ~/
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    touch ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys

    # 添加公钥（避免重复）
    if ! grep -q "$SSH_PUBKEY" ~/.ssh/authorized_keys 2>/dev/null; then
        echo "$SSH_PUBKEY" >> ~/.ssh/authorized_keys
    fi

    # 确保 SSH 配置允许公钥登录
    sed -i 's/^\s*#\?\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^\s*#\?\s*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/' /etc/ssh/sshd_config

    # 重启 SSH
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service sshd restart 2>/dev/null

    log_success "SSH 密钥登录配置完成"
}

# 13. 禁用密码登录
do_disable_password() {
    log_step "13. 禁用密码登录"

    # 检查是否已配置密钥登录
    if [ ! -f ~/.ssh/authorized_keys ] || [ ! -s ~/.ssh/authorized_keys ]; then
        log_warn "未检测到 SSH 密钥，跳过禁用密码登录（避免锁死）"
        return 0
    fi

    log_info "正在禁用密码登录..."

    # 禁用密码登录
    sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

    # 重启 SSH
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service sshd restart 2>/dev/null

    log_success "密码登录已禁用，只允许密钥登录"
}

# 14. fail2ban SSH 防御（kejilion f2b_install_sshd 函数）
do_fail2ban() {
    log_step "14. SSH 防御程序 (fail2ban)"

    log_info "正在安装 fail2ban..."

    # 移除可能存在的 docker 版本
    docker rm -f fail2ban >/dev/null 2>&1

    # 安装 fail2ban
    $PKG_INSTALL fail2ban

    # 启动并启用
    systemctl start fail2ban
    systemctl enable fail2ban

    # CentOS/RHEL 需要额外配置
    if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
        mkdir -p /etc/fail2ban/jail.d/
        cat > /etc/fail2ban/jail.d/sshd.conf << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 5
bantime = 3600
EOF
    fi

    # Debian/Ubuntu 需要 rsyslog
    if command -v apt &>/dev/null; then
        $PKG_INSTALL rsyslog
        systemctl start rsyslog
        systemctl enable rsyslog
    fi

    # 重载配置
    fail2ban-client reload 2>/dev/null

    log_success "fail2ban 安装完成"
}

# 15. 防火墙配置（开放必要端口）
do_firewall() {
    log_step "15. 防火墙配置"

    log_info "正在配置防火墙..."

    # 移除可能冲突的防火墙工具
    systemctl stop firewalld 2>/dev/null
    systemctl disable firewalld 2>/dev/null
    systemctl stop ufw 2>/dev/null
    systemctl disable ufw 2>/dev/null

    # 使用 iptables 开放端口
    if command -v iptables &>/dev/null; then
        # 开放 SSH 端口
        iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null
        # 开放常用端口
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
        # 允许 PING
        iptables -I INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null
    fi

    log_success "防火墙配置完成"
}

# 16. Docker 安装（kejilion linuxmirrors_install_docker 函数）
do_install_docker() {
    log_step "16. Docker 安装"

    # 检查是否已安装
    if command -v docker &>/dev/null; then
        log_success "Docker 已安装，跳过"
        return 0
    fi

    log_info "正在安装 Docker..."

    # 使用 kejilion 推荐的 linuxmirrors 脚本
    if [ "$IS_CHINA" = true ]; then
        bash <(curl -sSL https://linuxmirrors.cn/docker.sh) \
            --source mirrors.huaweicloud.com/docker-ce \
            --source-registry docker.1ms.run \
            --protocol https \
            --use-intranet-source false \
            --install-latest true \
            --close-firewall false \
            --ignore-backup-tips
    else
        bash <(curl -sSL https://linuxmirrors.cn/docker.sh) \
            --source download.docker.com \
            --source-registry registry.hub.docker.com \
            --protocol https \
            --use-intranet-source false \
            --install-latest true \
            --close-firewall false \
            --ignore-backup-tips
    fi

    # 配置 Docker 镜像加速（国内）
    if [ "$IS_CHINA" = true ]; then
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json << 'EOF'
{
    "registry-mirrors": [
        "https://docker.1ms.run",
        "https://docker.xuanyuan.me"
    ]
}
EOF
        systemctl daemon-reload
        systemctl restart docker
    fi

    # 验证安装
    if command -v docker &>/dev/null; then
        log_success "Docker 安装完成"
        docker --version
    else
        log_error "Docker 安装失败"
        return 1
    fi
}

# 17. Komari 监控探针
do_install_komari() {
    log_step "17. Komari 监控探针"

    # Komari 服务端配置
    KOMARI_SERVER="148.135.102.181:25774"
    KOMARI_TOKEN="${KOMARI_TOKEN:-}"  # 从环境变量获取，或留空跳过

    if [ -z "$KOMARI_TOKEN" ]; then
        log_warn "KOMARI_TOKEN 未设置，跳过探针安装"
        log_info "手动安装命令: docker run -d --name komari-agent --restart always ..."
        return 0
    fi

    log_info "正在安装 Komari 监控探针..."

    # 确保 Docker 已安装
    if ! command -v docker &>/dev/null; then
        log_error "Docker 未安装，跳过 Komari"
        return 1
    fi

    # 移除旧容器
    docker rm -f komari-agent 2>/dev/null

    # 安装 Komari Agent
    docker run -d \
        --name komari-agent \
        --restart always \
        --net=host \
        --pid=host \
        -v /:/host:ro \
        -v /var/run/docker.sock:/var/run/docker.sock:ro \
        ghcr.io/komari-monitor/komari-agent:latest \
        -s "${KOMARI_SERVER}" \
        -k "${KOMARI_TOKEN}"

    if [ $? -eq 0 ]; then
        log_success "Komari 探针安装完成"
    else
        log_error "Komari 探针安装失败"
        return 1
    fi
}

# 18. 基础工具安装
do_install_tools() {
    log_step "18. 基础工具安装"

    log_info "正在安装基础工具..."

    # kejilion 推荐的工具列表
    local tools="wget curl sudo tar unzip socat btop nano vim git htop"

    case "$PKG_MANAGER" in
        apt)
            apt update
            apt install -y $tools
            ;;
        yum)
            yum install -y epel-release
            yum install -y $tools
            ;;
        dnf)
            dnf install -y epel-release
            dnf install -y $tools
            ;;
    esac

    log_success "基础工具安装完成"
}

# ============================================================
# 主流程
# ============================================================

main() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                 VPS 一键初始化脚本                         ║"
    echo "║                   非交互式自动化                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # 前置检查
    check_root
    detect_os
    detect_location
    calc_swap_size

    # 自动获取 HOSTNAME（使用当前主机名）
    HOSTNAME=$(hostname)

    # 自动从 GitHub 获取 SSH 公钥
    log_info "从 GitHub 获取 SSH 公钥..."
    SSH_PUBKEY=$(curl -s "https://github.com/${GITHUB_USER}.keys" | head -1)
    if [ -z "$SSH_PUBKEY" ]; then
        log_warn "无法从 GitHub 获取公钥，将跳过密钥登录配置"
    else
        log_success "已获取 SSH 公钥"
    fi

    echo ""
    log_info "配置信息:"
    echo "  主机名:     $HOSTNAME"
    echo "  SSH端口:    $SSH_PORT"
    echo "  时区:       $TIMEZONE"
    echo "  SWAP大小:   ${SWAP_SIZE}MB"
    echo "  SSH公钥:    ${SSH_PUBKEY:0:50}..."
    echo ""

    # 倒计时
    log_warn "5 秒后开始初始化，按 Ctrl+C 取消..."
    sleep 5

    # 执行初始化步骤
    do_system_update        # 1. 系统更新
    do_system_clean         # 2. 系统清理
    do_switch_mirror        # 3. 切换更新源
    do_bbr3                 # 4. BBR3 加速
    do_kernel_optimize      # 5. 内核参数优化
    do_dns_optimize         # 6. DNS 优化
    do_ipv4_priority        # 7. IPv4 优先
    do_swap_setup           # 8. 虚拟内存
    do_timezone_setup       # 9. 时区设置
    do_hostname_setup       # 10. 主机名
    do_ssh_port             # 11. SSH 端口
    do_ssh_key              # 12. SSH 密钥
    do_disable_password     # 13. 禁用密码登录
    do_fail2ban             # 14. fail2ban
    do_firewall             # 15. 防火墙
    do_install_docker       # 16. Docker
    do_install_komari       # 17. Komari 探针
    do_install_tools        # 18. 基础工具

    # 显示完成信息
    echo ""
    log_step "初始化完成！"
    echo ""
    log_info "系统信息:"
    echo "  主机名:     $(hostname)"
    echo "  SSH端口:    $SSH_PORT"
    echo "  时区:       $(timedatectl | grep 'Time zone' | awk '{print $3}' 2>/dev/null || echo $TIMEZONE)"
    echo "  SWAP:       $(free -h | awk '/^Swap:/{print $2}')"
    echo "  Docker:     $(docker --version 2>/dev/null || echo '未安装')"
    echo ""
    log_warn "请使用新端口重新连接: ssh -p $SSH_PORT root@<IP>"
    echo ""
}

# 运行
main "$@"
