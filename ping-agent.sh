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
    echo '["'"$(echo "$input" | sed 's/,/","/g')"'"]'
  fi
}

# ---------- 平台识别 ----------
detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case $ARCH in
    x86_64) ARCH=amd64;;
    aarch64|arm64) ARCH=arm64;;
    *) echo "❌ Unsupported arch: $ARCH"; exit 1;;
  esac

  case $OS in
    linux*|darwin*) EXT="tar.gz";;
    windows*) EXT="zip";;
    *) echo "❌ Unsupported OS: $OS"; exit 1;;
  esac
}

# ---------- 获取 tag ----------
get_tag() {
  local version="${1:-latest}"
  local api="https://api.github.com/repos/${REPO}/releases"
  if [[ "$version" == "latest" ]]; then
    curl -fsSL "${api}/latest" | grep -Po '"tag_name":\s*"\K.*?(?=")'
  else
    echo "$version"
  fi
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
      *) echo "unknown arg $1"; exit 1;;
    esac
  done

  detect_platform
  TAG=$(get_tag "$VERSION")
  ASSET="ping-agent_${TAG#v}_${OS}_${ARCH}.${EXT}"
  DL_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

  echo "⬇️ Installing ping-agent $TAG for $OS/$ARCH ..."

  WORKDIR=$(mktemp -d)
  trap 'rm -rf "$WORKDIR"' EXIT
  cd "$WORKDIR"
  curl -fL# -o "$ASSET" "$DL_URL"

  case $EXT in
    tar.gz) tar -xzf "$ASSET";;
    zip) unzip -q "$ASSET";;
  esac

  BIN_DIR="/usr/local/bin"
  if [[ ! -w $BIN_DIR ]]; then
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    echo "⚠️  No root permission, installing to $BIN_DIR"
  fi

  install -m 0755 ping-agent "$BIN_DIR/ping-agent"
  setcap cap_net_raw+ep "$BIN_DIR/ping-agent" 2>/dev/null || true

  # 配置
  CONFIG_DIR="/etc/ping-agent"
  [[ -w /etc ]] || CONFIG_DIR="$HOME/.config/ping-agent"
  mkdir -p "$CONFIG_DIR"

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
  chmod 600 "$CONFIG_DIR/config.json"

  # systemd
  if command -v systemctl >/dev/null && [[ -w /etc/systemd/system ]]; then
    SERVICE=/etc/systemd/system/ping-agent.service
    cat <<EOF > $SERVICE
[Unit]
Description=Ping Agent
After=network.target

[Service]
ExecStart=$BIN_DIR/ping-agent $CONFIG_DIR/config.json
Restart=on-failure
AmbientCapabilities=CAP_NET_RAW
User=nobody
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now ping-agent
    echo "✅ ping-agent is running. Logs: journalctl -u ping-agent -f"
  else
    echo "✅ Installed. Run manually with:"
    echo "   $BIN_DIR/ping-agent $CONFIG_DIR/config.json"
  fi
}

# ---------- 更新 ----------
cmd_update() {
  VERSION="${1:-latest}"

  detect_bin
  if [[ -z "$BIN_PATH" ]]; then
    echo "❌ 未找到已安装的 ping-agent，请先安装"
    exit 1
  fi

  detect_platform
  TAG=$(get_tag "$VERSION")
  ASSET="ping-agent_${TAG#v}_${OS}_${ARCH}.${EXT}"
  DL_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

  echo "⬇️ Updating ping-agent to $TAG for $OS/$ARCH ..."

  WORKDIR=$(mktemp -d)
  trap 'rm -rf "$WORKDIR"' EXIT
  cd "$WORKDIR"

  if systemctl is-active --quiet ping-agent; then
    echo "→ 停止 systemd 服务"
    systemctl stop ping-agent
  fi

  curl -fL# -o "$ASSET" "$DL_URL"
  case $EXT in
    tar.gz) tar -xzf "$ASSET";;
    zip) unzip -q "$ASSET";;
  esac

  install -m 0755 ping-agent "$BIN_PATH"
  setcap cap_net_raw+ep "$BIN_PATH" 2>/dev/null || true

  if systemctl list-unit-files | grep -q ping-agent.service; then
    echo "→ 重启 systemd 服务"
    systemctl daemon-reload
    systemctl start ping-agent
    echo "✅ 更新完成，服务已重启"
  else
    echo "✅ 更新完成，可手动运行："
    echo "   $BIN_PATH /etc/ping-agent/config.json"
  fi
}

# ---------- 卸载 ----------
cmd_uninstall() {
  detect_bin
  CONFIG_DIR="/etc/ping-agent"
  [[ -d "$CONFIG_DIR" ]] || CONFIG_DIR="$HOME/.config/ping-agent"

  echo "🔍 正在卸载 ping-agent ..."

  if systemctl list-unit-files | grep -q ping-agent.service; then
    echo "→ 停止并删除 systemd 服务"
    systemctl stop ping-agent || true
    systemctl disable ping-agent || true
    rm -f /etc/systemd/system/ping-agent.service
    systemctl daemon-reload || true
  fi

  if [[ -n "$BIN_PATH" ]]; then
    echo "→ 删除二进制 $BIN_PATH"
    rm -f "$BIN_PATH"
  fi

  if [[ -d "$CONFIG_DIR" ]]; then
    echo "→ 删除配置目录 $CONFIG_DIR"
    rm -rf "$CONFIG_DIR"
  fi

  echo "✅ 卸载完成"
}

# ---------- 主入口 ----------
case "${1:-}" in
  install) shift; cmd_install "$@";;
  update) shift; cmd_update "$@";;
  uninstall) shift; cmd_uninstall "$@";;
  *) echo "用法: $0 {install|update|uninstall}"; exit 1;;
esac
