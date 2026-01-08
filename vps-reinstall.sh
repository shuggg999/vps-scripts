#!/bin/bash
#
# VPS 系统重装脚本 - Debian 12
# 基于 kejilion dd_xitong 函数，使用 leitbogioro/Tools 脚本
#
# 使用方法：
#   bash vps-reinstall.sh
#
# 重装后信息：
#   用户名: root
#   密码:   LeitboGi0ro
#   端口:   22
#
# ============================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# GitHub 代理（国内服务器可能需要，留空则不使用）
gh_proxy=""

# ============================================================
# 主流程
# ============================================================

main() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              VPS 系统重装 - Debian 12                      ║"
    echo "║              基于 leitbogioro/Tools 脚本                   ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # 检查 root
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}[ERROR] 请使用 root 用户运行此脚本${NC}"
        exit 1
    fi

    # 显示重装后信息
    echo ""
    echo -e "${YELLOW}================================================${NC}"
    echo -e "重装后初始信息："
    echo -e "  用户名: ${GREEN}root${NC}"
    echo -e "  密码:   ${GREEN}LeitboGi0ro${NC}"
    echo -e "  端口:   ${GREEN}22${NC}"
    echo -e "${YELLOW}================================================${NC}"
    echo ""
    echo -e "${RED}警告: 重装系统将清除所有数据！${NC}"
    echo -e "${RED}预计需要 10-15 分钟，期间无法连接服务器${NC}"
    echo ""

    # 确认
    read -p "确认重装为 Debian 12？(y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "取消重装"
        exit 0
    fi

    # 下载 leitbogioro 重装脚本（kejilion 原版命令）
    echo ""
    echo -e "${CYAN}[INFO]${NC} 下载重装脚本..."
    wget --no-check-certificate -qO InstallNET.sh "${gh_proxy}https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh" && chmod a+x InstallNET.sh

    if [ ! -f InstallNET.sh ]; then
        echo -e "${RED}[ERROR] 下载失败${NC}"
        exit 1
    fi

    # 执行重装（kejilion 原版命令）
    echo -e "${CYAN}[INFO]${NC} 开始重装 Debian 12..."
    bash InstallNET.sh -debian 12

    # 重启
    echo ""
    echo -e "${GREEN}重装命令已执行，系统即将重启...${NC}"
    echo -e "${YELLOW}请等待 10-15 分钟后使用以下信息连接：${NC}"
    echo -e "  ssh root@<IP> -p 22"
    echo -e "  密码: LeitboGi0ro"
    echo ""
    reboot
}

main "$@"
