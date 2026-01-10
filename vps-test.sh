#!/bin/bash
# VPS 综合测试脚本 - 无交互版
# 基于 spiritlhl/ecs 融合怪优化
# 测试项：基础信息 + CPU + 磁盘IO + 回程路由 + 流媒体解锁 + IP质量
# 约 3-5 分钟完成

# set -e  # 禁用，避免某个命令失败导致整个脚本退出

# ==================== 颜色定义 ====================
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

_red() { echo -e "${RED}$*${PLAIN}"; }
_green() { echo -e "${GREEN}$*${PLAIN}"; }
_yellow() { echo -e "${YELLOW}$*${PLAIN}"; }
_blue() { echo -e "${BLUE}$*${PLAIN}"; }

# ==================== 全局变量 ====================
TEMP_DIR="/tmp/vps-test"
ARCH=$(uname -m)
START_TIME=$(date +%s)

# 三网测试目标IP
declare -A TEST_TARGETS=(
    ["广州电信"]="58.60.188.222"
    ["广州联通"]="210.21.196.6"
    ["广州移动"]="120.196.165.24"
)

# ==================== 工具函数 ====================
check_root() {
    [[ $EUID -ne 0 ]] && { _red "请使用 root 用户运行此脚本"; exit 1; }
}

init_env() {
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    # 设置 locale
    export LC_ALL=C.UTF-8 2>/dev/null || export LC_ALL=C
    export LANG=C.UTF-8 2>/dev/null || export LANG=C
}

get_arch_file() {
    case "$ARCH" in
        x86_64) echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *) echo "386" ;;
    esac
}

download_tool() {
    local name=$1
    local url=$2
    local output=$3

    if [[ ! -f "$output" ]]; then
        curl -sL "$url" -o "$output" 2>/dev/null && chmod +x "$output"
    fi
}

# ==================== 基础信息 ====================
get_system_info() {
    echo ""
    echo "---------------------基础信息---------------------"

    # CPU 信息
    local cpu_model=$(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)
    local cpu_cores=$(nproc)
    local cpu_freq=$(grep 'cpu MHz' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)

    # 内存信息
    local mem_total=$(free -m | awk '/Mem:/{print $2}')
    local mem_used=$(free -m | awk '/Mem:/{print $3}')
    local swap_total=$(free -m | awk '/Swap:/{print $2}')

    # 硬盘信息
    local disk_total=$(df -h / | awk 'NR==2{print $2}')
    local disk_used=$(df -h / | awk 'NR==2{print $3}')

    # 系统信息
    local os_release=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)
    local kernel=$(uname -r)
    local virt=$(systemd-detect-virt 2>/dev/null || echo "unknown")

    # AES-NI 检测
    local aes_ni="❌ Disabled"
    grep -q aes /proc/cpuinfo && aes_ni="✔ Enabled"

    # TCP 加速
    local tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")

    echo -e " CPU 型号       : ${BLUE}${cpu_model}${PLAIN}"
    echo -e " CPU 核心数     : ${BLUE}${cpu_cores}${PLAIN}"
    echo -e " CPU 频率       : ${BLUE}${cpu_freq} MHz${PLAIN}"
    echo -e " AES-NI         : ${BLUE}${aes_ni}${PLAIN}"
    echo -e " 内存           : ${BLUE}${mem_used}M / ${mem_total}M${PLAIN}"
    echo -e " Swap           : ${BLUE}${swap_total}M${PLAIN}"
    echo -e " 硬盘           : ${BLUE}${disk_used} / ${disk_total}${PLAIN}"
    echo -e " 系统           : ${BLUE}${os_release}${PLAIN}"
    echo -e " 内核           : ${BLUE}${kernel}${PLAIN}"
    echo -e " 虚拟化         : ${BLUE}${virt}${PLAIN}"
    echo -e " TCP 加速       : ${YELLOW}${tcp_cc}${PLAIN}"
}

get_ip_info() {
    echo ""
    echo "---------------------IP 信息----------------------"

    local ip_info=$(curl -s ipinfo.io 2>/dev/null)
    local ip=$(echo "$ip_info" | grep -oP '"ip": "\K[^"]+' | head -1)
    local city=$(echo "$ip_info" | grep -oP '"city": "\K[^"]+')
    local region=$(echo "$ip_info" | grep -oP '"region": "\K[^"]+')
    local country=$(echo "$ip_info" | grep -oP '"country": "\K[^"]+')
    local org=$(echo "$ip_info" | grep -oP '"org": "\K[^"]+')

    echo -e " IPv4 地址      : ${BLUE}${ip}${PLAIN}"
    echo -e " 位置           : ${BLUE}${city} / ${region} / ${country}${PLAIN}"
    echo -e " ASN            : ${BLUE}${org}${PLAIN}"
}

# ==================== CPU 测试 ====================
test_cpu() {
    echo ""
    echo "---------------------CPU 测试---------------------"

    # 检查/安装 sysbench
    if ! command -v sysbench &>/dev/null; then
        _yellow "安装 sysbench..."
        apt-get update -qq && apt-get install -y -qq sysbench >/dev/null 2>&1 || \
        yum install -y epel-release sysbench >/dev/null 2>&1 || \
        { _red "sysbench 安装失败，跳过 CPU 测试"; return; }
    fi

    echo -e " ${YELLOW}-> CPU 测试中 (单线程, 5秒)${PLAIN}"

    # 使用融合怪相同的参数: cpu-max-prime=10000
    local result=$(sysbench cpu --threads=1 --cpu-max-prime=10000 --events=1000000 --time=5 run 2>/dev/null)

    # 优先从 "events per second" 获取得分
    local score=$(echo "$result" | grep -oE "events per second:\s*[0-9.]+" | grep -oE "[0-9.]+")

    # 备用：从 total events / total time 计算
    if [[ -z "$score" ]]; then
        local events=$(echo "$result" | grep "total number of events" | awk '{print $NF}')
        local time=$(echo "$result" | grep "total time:" | grep -oE "[0-9.]+" | head -1)
        score=$(echo "$events $time" | awk '{printf "%.0f", $1/$2}')
    fi

    echo -e " 单核得分       : ${BLUE}${score} Scores${PLAIN}"

    # 评级
    local rating=""
    if [[ ${score%.*} -gt 1200 ]]; then rating="⭐⭐⭐⭐⭐ 顶级"
    elif [[ ${score%.*} -gt 900 ]]; then rating="⭐⭐⭐⭐ 优秀"
    elif [[ ${score%.*} -gt 600 ]]; then rating="⭐⭐⭐ 良好"
    elif [[ ${score%.*} -gt 400 ]]; then rating="⭐⭐ 一般"
    else rating="⭐ 较差"
    fi
    echo -e " 评级           : ${GREEN}${rating}${PLAIN}"
}

# ==================== 磁盘测试 ====================
test_disk_dd() {
    echo ""
    echo "---------------------磁盘 IO 测试-----------------"
    echo -e " ${YELLOW}-> 磁盘测试中 (dd 直写模式)${PLAIN}"

    # 清理缓存
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true

    # 写入测试 (1GB)
    local write_result=$(dd if=/dev/zero of="$TEMP_DIR/test_write" bs=1M count=1024 conv=fdatasync 2>&1)
    local write_speed=$(echo "$write_result" | grep -oE '[0-9.]+ [MG]B/s' | tail -1)
    rm -f "$TEMP_DIR/test_write"

    # 读取测试
    dd if=/dev/zero of="$TEMP_DIR/test_read" bs=1M count=1024 2>/dev/null
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    local read_result=$(dd if="$TEMP_DIR/test_read" of=/dev/null bs=1M 2>&1)
    local read_speed=$(echo "$read_result" | grep -oE '[0-9.]+ [MG]B/s' | tail -1)
    rm -f "$TEMP_DIR/test_read"

    echo -e " 写入速度       : ${BLUE}${write_speed}${PLAIN}"
    echo -e " 读取速度       : ${BLUE}${read_speed}${PLAIN}"

    # 评级
    local speed_num=$(echo "$write_speed" | grep -oE '[0-9.]+')
    local unit=$(echo "$write_speed" | grep -oE '[MG]B')
    [[ "$unit" == "GB" ]] && speed_num=$(echo "$speed_num * 1000" | bc 2>/dev/null || echo "1000")

    local rating=""
    if (( $(echo "$speed_num > 1000" | bc -l 2>/dev/null || echo 0) )); then rating="⭐⭐⭐⭐⭐ 顶级 (NVMe)"
    elif (( $(echo "$speed_num > 500" | bc -l 2>/dev/null || echo 0) )); then rating="⭐⭐⭐⭐ 优秀 (SSD)"
    elif (( $(echo "$speed_num > 300" | bc -l 2>/dev/null || echo 0) )); then rating="⭐⭐⭐ 良好"
    elif (( $(echo "$speed_num > 100" | bc -l 2>/dev/null || echo 0) )); then rating="⭐⭐ 一般"
    else rating="⭐ 较差"
    fi
    echo -e " 评级           : ${GREEN}${rating}${PLAIN}"
}

# ==================== 回程路由测试 ====================
test_route() {
    echo ""
    echo "---------------------三网回程路由-----------------"

    local arch_file=$(get_arch_file)

    # 下载 backtrace
    local bt_url="https://github.com/oneclickvirt/backtrace/releases/download/output/backtrace-linux-${arch_file}"
    download_tool "backtrace" "$bt_url" "$TEMP_DIR/backtrace"

    # 下载 nexttrace
    local nt_url="https://github.com/nxtrace/NTrace-core/releases/latest/download/nexttrace_linux_${arch_file}"
    download_tool "nexttrace" "$nt_url" "$TEMP_DIR/nexttrace"

    # backtrace 快速检测
    echo ""
    echo ">>> 快速线路检测 (backtrace)"
    if [[ -f "$TEMP_DIR/backtrace" ]]; then
        "$TEMP_DIR/backtrace" 2>/dev/null | grep -v 'github.com' | grep -v '正在测试' | grep -v '测试完成' || true
    else
        _yellow "backtrace 下载失败"
    fi

    # nexttrace 详细路由
    echo ""
    echo ">>> 详细回程路由 (nexttrace)"
    if [[ -f "$TEMP_DIR/nexttrace" ]]; then
        for name in "广州电信" "广州联通" "广州移动"; do
            local ip="${TEST_TARGETS[$name]}"
            echo ""
            _yellow "$name $ip"
            # 使用 --no-color 避免颜色代码干扰，--queries=1 减少探测次数
            local trace_result=$("$TEMP_DIR/nexttrace" --queries=1 --no-color "$ip" 2>/dev/null)
            echo "$trace_result" | grep -E "^\s*[0-9]+\s+[0-9.]+\s+ms|AS[0-9]+" | head -15 || \
            echo "$trace_result" | grep -v "^$" | head -15 || true
        done
    else
        _yellow "nexttrace 下载失败"
    fi
}

# ==================== 流媒体解锁 ====================
test_unlock() {
    echo ""
    echo "---------------------流媒体解锁-------------------"

    local arch_file=$(get_arch_file)
    local unlock_url="https://github.com/oneclickvirt/UnlockTests/releases/download/output/ut-linux-${arch_file}"
    download_tool "unlock" "$unlock_url" "$TEMP_DIR/unlock"

    if [[ -f "$TEMP_DIR/unlock" && -x "$TEMP_DIR/unlock" ]]; then
        # 输入 0 选择"跨国平台"检测，等待完成
        echo "0" | "$TEMP_DIR/unlock" 2>/dev/null | \
            grep -E "跨国平台|ChatGPT|Claude|Netflix|Disney|YouTube|TikTok|Gemini|Sora|Google|Apple|Spotify|Amazon|Steam" | \
            grep -v "请选择\|项目地址\|IPV4\|IPV6" | head -25
    else
        # 手动检测核心服务
        _yellow "使用手动检测模式..."

        echo -n " ChatGPT: "
        local chatgpt=$(curl -s --max-time 10 "https://api.openai.com/v1/models" 2>/dev/null)
        [[ "$chatgpt" != *"error"* && "$chatgpt" != *"blocked"* ]] && _green "YES" || _red "NO"

        echo -n " Claude: "
        local claude=$(curl -sI --max-time 10 "https://claude.ai" 2>/dev/null | grep -i "location\|HTTP")
        [[ "$claude" == *"200"* || "$claude" != *"blocked"* ]] && _green "YES" || _red "NO"

        echo -n " Netflix: "
        local netflix=$(curl -s --max-time 10 "https://www.netflix.com/title/80018499" 2>/dev/null)
        [[ "$netflix" == *"page-404"* || "$netflix" == *"Not Available"* ]] && _red "NO" || _green "可能解锁"

        echo -n " YouTube: "
        local youtube=$(curl -sI --max-time 10 "https://www.youtube.com" 2>/dev/null | head -1)
        [[ "$youtube" == *"200"* ]] && _green "YES" || _red "NO"
    fi
}

# ==================== IP 质量检测 ====================
test_ip_quality() {
    echo ""
    echo "---------------------IP 质量检测------------------"

    local arch_file=$(get_arch_file)
    local sec_url="https://github.com/oneclickvirt/securityCheck/releases/download/output/securityCheck-linux-${arch_file}"
    download_tool "security" "$sec_url" "$TEMP_DIR/security"

    if [[ -f "$TEMP_DIR/security" ]]; then
        "$TEMP_DIR/security" 2>/dev/null | grep -E "得分|Score|代理|VPN|Proxy|Tor|黑名单|Blacklist|Datacenter|数据中心" | head -15 || true
    else
        _yellow "IP质量检测工具下载失败"
    fi
}

# ==================== 清理 ====================
cleanup() {
    rm -rf "$TEMP_DIR"
}

# ==================== 主函数 ====================
main() {
    check_root
    init_env

    echo "############################################################"
    echo "#                   VPS 综合测试脚本                        #"
    echo "#          基于 spiritlhl/ecs 融合怪优化                   #"
    echo "############################################################"
    echo ""
    echo "测试时间: $(date '+%Y-%m-%d %H:%M:%S')"

    get_system_info
    get_ip_info
    test_cpu
    test_disk_dd
    test_route
    test_unlock
    test_ip_quality

    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    echo ""
    echo "------------------------------------------------------------"
    echo "总耗时: ${duration} 秒"
    echo "完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "------------------------------------------------------------"

    cleanup
}

main "$@"
