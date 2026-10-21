#!/usr/bin/env bash
#
# PingAgent 管理脚本
#
# 用法：
#   ./ping-agent.sh install [--token xxx --listen ":8080" --allow-ips "127.0.0.1" --allow-domains "example.com" --version latest]
#   ./ping-agent.sh update [version]
#   ./ping-agent.sh uninstall
#
set -euo pipefail

REPO="ProxyPanel/PingAgent"

BIN_PATH=""
CONFIG_DIR=""

# ---------- 检查二进制路径 ----------
detect_bin() {
  if [[ -x "/usr/local/bin/ping-agent" ]]; then
    BIN_PATH="/usr/local/bin/ping-agent"
  elif [[ -x "$HOME/.local/bin/ping-agent" ]]; then
    BIN_PATH="$HOME/.local/bin/ping-agent"
  else
    BIN_PATH=""
  fi
}

# ---------- JSON 数组生成 ----------
json_array() {
  local input="$1"
  if [[ -z "$input" ]]; then
    echo "[]"
  else
    # 修复：处理特殊字符和空格，确保 JSON 格式正确
    echo "$input" | sed 's/,/\n/g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
    jq -R . | jq -s .
  fi
}

# ---------- 平台识别 ----------
detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case $ARCH in
    x86_64) ARCH=amd64;;
    aarch64|arm64) ARCH=arm64;;
    i386|i686) ARCH=386;;  # 新增：支持 32 位
    *) echo "❌ Unsupported arch: $ARCH"; exit 1;;
  esac

  case $OS in
    linux*) OS="linux"; EXT="tar.gz";;
    darwin*) OS="darwin"; EXT="tar.gz";;
    windows*) OS="windows"; EXT="zip";;
    *) echo "❌ Unsupported OS: $OS"; exit 1;;
  esac
}

# ---------- 获取 tag ----------
get_tag() {
  local version="${1:-latest}"
  local api="https://api.github.com/repos/${REPO}/releases"
  if [[ "$version" == "latest" ]]; then
    # 修复：更可靠的 JSON 解析
    if command -v jq >/dev/null 2>&1; then
      curl -fsSL "${api}/latest" | jq -r '.tag_name'
    else
      curl -fsSL "${api}/latest" | grep -Po '"tag_name":\s*"\K.*?(?=")'
    fi
  else
    echo "$version"
  fi
}

# ---------- 验证下载的文件 ----------
verify_download() {
  local file="$1"
  local expected_size="$2"
  
  if [[ ! -f "$file" ]]; then
    echo "❌ 下载失败：文件不存在"
    return 1
  fi
  
  local actual_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
  if [[ "$actual_size" -lt 1000 ]]; then  # 小于 1KB 可能是错误页面
    echo "❌ 下载失败：文件大小异常 ($actual_size bytes)"
    return 1
  fi
  
  return 0
}

# ---------- 安装 ----------
cmd_install() {
  # 默认参数
  VERSION="latest"
  HTTP_LISTEN=":8080"
  TOKEN=""
  ALLOW_IPS=""
  ALLOW_DOMAINS=""

  # 解析参数
  while [[ $# -gt 0 ]]; do
    case $1 in
      --version)        VERSION="$2"; shift 2;;
      --listen)         HTTP_LISTEN="$2"; shift 2;;
      --token)          TOKEN="$2"; shift 2;;
      --allow-ips)      ALLOW_IPS="$2"; shift 2;;
      --allow-domains)  ALLOW_DOMAINS="$2"; shift 2;;
      *) echo "❌ Unknown argument: $1"; exit 1;;
    esac
  done

  # 检查是否已安装
  detect_bin
  if [[ -n "$BIN_PATH" ]]; then
    echo "⚠️  ping-agent 已安装在 $BIN_PATH"
    echo "   如需更新，请使用: $0 update"
    exit 1
  fi

  detect_platform
  TAG=$(get_tag "$VERSION")
  
  # 修复：文件名格式匹配 GoReleaser 输出
  ASSET="ping-agent_${TAG}_${OS}_${ARCH}.${EXT}"
  DL_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

  echo "⬇️  Installing ping-agent $TAG for $OS/$ARCH ..."
  echo "📦 Download URL: $DL_URL"

  WORKDIR=$(mktemp -d)
  trap 'rm -rf "$WORKDIR"' EXIT
  cd "$WORKDIR"
  
  # 下载并验证
  if ! curl -fL -o "$ASSET" "$DL_URL"; then
    echo "❌ 下载失败，请检查网络连接和版本号"
    exit 1
  fi
  
  if ! verify_download "$ASSET" 0; then
    exit 1
  fi

  # 解压
  case $EXT in
    tar.gz) 
      if ! tar -xzf "$ASSET"; then
        echo "❌ 解压 tar.gz 失败"
        exit 1
      fi
      ;;
    zip) 
      if ! unzip -q "$ASSET"; then
        echo "❌ 解压 zip 失败"
        exit 1
      fi
      ;;
  esac

  # 检查解压后的二进制文件
  if [[ ! -f "ping-agent" ]]; then
    echo "❌ 解压后未找到 ping-agent 二进制文件"
    ls -la
    exit 1
  fi

  # 安装二进制文件
  BIN_DIR="/usr/local/bin"
  if [[ ! -w "$BIN_DIR" ]]; then
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    echo "⚠️  No root permission, installing to $BIN_DIR"
    
    # 检查 PATH
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
      echo "⚠️  $BIN_DIR 不在 PATH 中，建议添加到 ~/.bashrc 或 ~/.zshrc："
      echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
  fi

  if ! install -m 0755 ping-agent "$BIN_DIR/ping-agent"; then
    echo "❌ 安装二进制文件失败"
    exit 1
  fi
  
  # 设置 capabilities (允许失败)
  setcap cap_net_raw+ep "$BIN_DIR/ping-agent" 2>/dev/null || {
    echo "⚠️  无法设置 CAP_NET_RAW，ping 功能可能需要 root 权限"
  }

  # 配置文件
  CONFIG_DIR="/etc/ping-agent"
  if [[ ! -w /etc ]]; then
    CONFIG_DIR="$HOME/.config/ping-agent"
  fi
  mkdir -p "$CONFIG_DIR"

  # 生成配置文件，使用 jq 确保 JSON 格式正确
  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg listen "$HTTP_LISTEN" \
      --arg token "$TOKEN" \
      --argjson allow_ips "$(json_array "$ALLOW_IPS")" \
      --argjson allow_domains "$(json_array "$ALLOW_DOMAINS")" \
      '{
        http_listen: $listen,
        auth: {
          token: $token,
          allow_ips: $allow_ips,
          allow_domains: $allow_domains
        }
      }' > "$CONFIG_DIR/config.json"
  else
    # 回退到原始方法
    cat <<EOF > "$CONFIG_DIR/config.json"
{
  "http_listen": "$HTTP_LISTEN",
  "auth": {
    "token": "$TOKEN",
    "allow_ips": $(json_array "$ALLOW_IPS"),
    "allow_domains": $(json_array "$ALLOW_DOMAINS")
  }
}
EOF
  fi

  chmod 644 "$CONFIG_DIR/config.json"
  chown root:root "$CONFIG_DIR/config.json" 2>/dev/null || true

  # systemd 服务
  if command -v systemctl >/dev/null && [[ -w /etc/systemd/system ]]; then
    SERVICE=/etc/systemd/system/ping-agent.service
    cat <<EOF > "$SERVICE"
[Unit]
Description=Ping Agent
After=network.target

[Service]
ExecStart=$BIN_DIR/ping-agent $CONFIG_DIR/config.json
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_RAW
User=nobody
Group=nogroup
NoNewPrivileges=true
# 安全加固
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ping-agent
    
    if systemctl start ping-agent; then
      echo "✅ ping-agent 安装成功并已启动"
      echo "📊 查看状态: systemctl status ping-agent"
      echo "📝 查看日志: journalctl -u ping-agent -f"
    else
      echo "❌ systemd 服务启动失败，请检查日志："
      echo "   journalctl -u ping-agent --no-pager"
    fi
  else
    echo "✅ 安装完成，手动启动命令："
    echo "   $BIN_DIR/ping-agent $CONFIG_DIR/config.json"
  fi
  
  echo ""
  echo "📄 配置文件位置: $CONFIG_DIR/config.json"
  echo "🔧 修改配置后重启服务: systemctl restart ping-agent"
}

# ---------- 更新 ----------
cmd_update() {
  VERSION="${1:-latest}"

  detect_bin
  if [[ -z "$BIN_PATH" ]]; then
    echo "❌ 未找到已安装的 ping-agent，请先使用 install 命令安装"
    exit 1
  fi

  detect_platform
  TAG=$(get_tag "$VERSION")
  
  # 检查是否已是最新版本
  if command -v "$BIN_PATH" >/dev/null 2>&1; then
    CURRENT_VERSION=$("$BIN_PATH" --version 2>/dev/null | grep -o 'v[0-9.]*' || echo "unknown")
    if [[ "$CURRENT_VERSION" == "$TAG" ]]; then
      echo "✅ 已是最新版本 $TAG"
      exit 0
    fi
    echo "📈 从 $CURRENT_VERSION 更新到 $TAG"
  fi
  
  ASSET="ping-agent_${TAG}_${OS}_${ARCH}.${EXT}"
  DL_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

  echo "⬇️  Updating ping-agent to $TAG for $OS/$ARCH ..."

  WORKDIR=$(mktemp -d)
  trap 'rm -rf "$WORKDIR"' EXIT
  cd "$WORKDIR"

  # 停止服务
  if systemctl is-active --quiet ping-agent 2>/dev/null; then
    echo "→ 停止 systemd 服务"
    systemctl stop ping-agent
  fi

  # 下载并验证
  if ! curl -fL -o "$ASSET" "$DL_URL"; then
    echo "❌ 下载失败"
    # 如果停止了服务，尝试重启
    if systemctl list-unit-files | grep -q ping-agent.service; then
      systemctl start ping-agent || true
    fi
    exit 1
  fi
  
  if ! verify_download "$ASSET" 0; then
    exit 1
  fi

  # 解压
  case $EXT in
    tar.gz) tar -xzf "$ASSET";;
    zip) unzip -q "$ASSET";;
  esac

  # 备份旧版本
  if [[ -f "$BIN_PATH" ]]; then
    cp "$BIN_PATH" "$BIN_PATH.backup.$(date +%Y%m%d_%H%M%S)"
  fi

  # 安装新版本
  if ! install -m 0755 ping-agent "$BIN_PATH"; then
    echo "❌ 更新失败，尝试恢复服务"
    if systemctl list-unit-files | grep -q ping-agent.service; then
      systemctl start ping-agent || true
    fi
    exit 1
  fi
  
  setcap cap_net_raw+ep "$BIN_PATH" 2>/dev/null || true

  # 重启服务
  if systemctl list-unit-files | grep -q ping-agent.service; then
    echo "→ 重启 systemd 服务"
    systemctl daemon-reload
    if systemctl start ping-agent; then
      echo "✅ 更新完成，服务已重启"
    else
      echo "❌ 服务重启失败，请检查日志："
      echo "   journalctl -u ping-agent --no-pager"
    fi
  else
    echo "✅ 更新完成，可手动运行："
    echo "   $BIN_PATH $CONFIG_DIR/config.json"
  fi
}

# ---------- 卸载 ----------
cmd_uninstall() {
  detect_bin
  CONFIG_DIR="/etc/ping-agent"
  [[ -d "$CONFIG_DIR" ]] || CONFIG_DIR="$HOME/.config/ping-agent"

  echo "🔍 正在卸载 ping-agent ..."

  # 停止并删除 systemd 服务
  if systemctl list-unit-files 2>/dev/null | grep -q ping-agent.service; then
    echo "→ 停止并删除 systemd 服务"
    systemctl stop ping-agent 2>/dev/null || true
    systemctl disable ping-agent 2>/dev/null || true
    rm -f /etc/systemd/system/ping-agent.service
    systemctl daemon-reload 2>/dev/null || true
  fi

  # 删除二进制文件
  if [[ -n "$BIN_PATH" && -f "$BIN_PATH" ]]; then
    echo "→ 删除二进制文件 $BIN_PATH"
    rm -f "$BIN_PATH"
    # 删除备份文件
    rm -f "$BIN_PATH".backup.*
  fi

  # 删除配置目录
  if [[ -d "$CONFIG_DIR" ]]; then
    read -p "🗑️  是否删除配置目录 $CONFIG_DIR? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      echo "→ 删除配置目录 $CONFIG_DIR"
      rm -rf "$CONFIG_DIR"
    else
      echo "→ 保留配置目录 $CONFIG_DIR"
    fi
  fi

  echo "✅ 卸载完成"
}

# ---------- 显示状态 ----------
cmd_status() {
  detect_bin
  
  if [[ -z "$BIN_PATH" ]]; then
    echo "❌ ping-agent 未安装"
    exit 1
  fi
  
  echo "📍 二进制文件: $BIN_PATH"
  
  if command -v "$BIN_PATH" >/dev/null 2>&1; then
    VERSION=$("$BIN_PATH" --version 2>/dev/null || echo "unknown")
    echo "📊 版本: $VERSION"
  fi
  
  CONFIG_DIR="/etc/ping-agent"
  [[ -d "$CONFIG_DIR" ]] || CONFIG_DIR="$HOME/.config/ping-agent"
  
  if [[ -f "$CONFIG_DIR/config.json" ]]; then
    echo "📄 配置文件: $CONFIG_DIR/config.json"
  fi
  
  if systemctl list-unit-files 2>/dev/null | grep -q ping-agent.service; then
    echo "🔄 systemd 服务状态:"
    systemctl status ping-agent --no-pager -l
  else
    echo "⚠️  未配置 systemd 服务"
  fi
}

# ---------- 主入口 ----------

# 处理通过管道执行的情况
if [[ "${BASH_SOURCE[0]:-}" != "${0}" ]] && [[ $# -eq 0 ]]; then
  # 脚本通过管道执行但没有参数，显示帮助
  echo "⚠️  通过管道执行需要提供参数"
  echo ""
fi

case "${1:-}" in
  install) shift; cmd_install "$@";;
  update) shift; cmd_update "$@";;
  uninstall) shift; cmd_uninstall "$@";;
  status) shift; cmd_status "$@";;
  *) 
    echo "用法: $0 {install|update|uninstall|status}"
    echo ""
    echo "命令："
    echo "  install   - 安装 ping-agent"
    echo "  update    - 更新 ping-agent"
    echo "  uninstall - 卸载 ping-agent"
    echo "  status    - 查看状态"
    echo ""
    echo "install 参数："
    echo "  --version VERSION     版本号 (默认: latest)"
    echo "  --listen ADDR         监听地址 (默认: :8080)"
    echo "  --token TOKEN         认证 token"
    echo "  --allow-ips IPS       允许的 IP 列表，逗号分隔"
    echo "  --allow-domains DOMS  允许的域名列表，逗号分隔"
    exit 1
    ;;
esac