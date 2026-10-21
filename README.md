# PingAgent

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue)](https://golang.org) [![License](https://img.shields.io/badge/License-GPL--3.0-green)](LICENSE) [![Version](https://img.shields.io/badge/Version-0.1.4-green)]()

轻量级网络连通性探测器 / 多节点主动监控组件

Lightweight Network Probe for Multi-Node Active Monitoring

---

## ✨ 核心特性

- 🚀 **并发探测** - 并发探测 ICMP 和 TCP，每次探测进行 3 次并发采样取平均值
- 🔒 **安全访问** - 支持 Token 认证、IP 白名单、域名白名单
- 💾 **智能缓存** - DNS 解析缓存、域名 IP 映射缓存，减少重复查询
- 🌐 **双栈支持** - 完整支持 IPv4 和 IPv6
- ⚡ **限流保护** - 内置并发限流，防止资源耗尽
- 🔧 **灵活配置** - JSON 配置文件，支持多种认证和访问控制方式
- 📊 **精确测量** - 多次采样取平均值，提供更准确的延迟数据

## 快速开始

### 编译安装

环境要求

- Go 1.27+
- Linux/macOS/Windows

```bash
# 克隆仓库
git clone https://github.com/ProxyPanel/PingAgent.git
cd PingAgent

# 安装依赖
go mod tidy

# 编译
go build -o ping-agent ./cmd/agent

# 带版本信息编译
go build -ldflags "-X main.Version=v1.0.0" -o ping-agent ./cmd/agent

# Linux: 赋予ICMP权限（可选）
sudo setcap cap_net_raw+ep ./ping-agent

# macOS: 需要sudo运行或接受UDP降级
```

### 脚本安装

```bash
curl -sSfL https://cdn.jsdelivr.net/gh/ProxyPanel/PingAgent@main/ping-agent.sh | \
bash -s -- install \
  --token '123456' \
  --listen ":8080" \
  --allow-ips "127.0.0.1,10.0.0.0/8" \
  --allow-domains "control.example.com" \
  --version latest
```

> 如果 jsDelivr 取不到，可把 URL 换成 `https://raw.githubusercontent.com/ProxyPanel/PingAgent/main/ping-agent.sh` 回源 GitHub。

#### 更新

```bash
# 默认是最新版本
./ping-agent.sh update

# 指定版本
./ping-agent.sh update v1.2.3
```

#### 卸载

```bash
./ping-agent.sh uninstall
```

## 配置

创建 `config.json` 配置文件：

```json
{
  "http_listen": ":8080",
  "dns_servers": ["223.5.5.5", "8.8.8.8"],
  "auth": {
    "token": "ChangeMeIfNeeded",
    "allow_ips": ["192.168.1.0/24", "10.0.0.1", "172.16.0.0/16"],
    "allow_domains": ["trusted.example.com", "api.partner.com"],
    "trusted_proxies": ["127.0.0.1", "10.0.0.0/8"]
  }
}
```

配置说明

| 字段                | 说明                                                        | 默认值         |
| ------------------- | ----------------------------------------------------------- | -------------- |
| http_listen         | HTTP 监听地址                                               | :8080          |
| dns_servers         | 自定义 DNS（IP 或 IP:port）；留空继承宿主机                 | 空             |
| auth.token          | Bearer Token 认证令牌                                       | 空（不启用）   |
| auth.allow_ips      | IP 白名单列表，支持 CIDR                                    | 空（允许所有） |
| auth.allow_domains  | 域名白名单列表（启动时预热，热路径只读缓存）                | 空（允许所有） |
| auth.trusted_proxies| 可信代理 IP/CIDR 列表；仅当直连来源在此列表内才采信 XFF     | 空             |

> 安全默认：`X-Forwarded-For` / `X-Real-IP` 只在直连来源属于 `trusted_proxies` 时才用于白名单匹配，防止伪造头绕过 IP 白名单。裸监听公网时无需设置；确在反向代理后面，把代理地址加入 `trusted_proxies`。

## 使用方法

### 启动服务

```bash
# 使用配置文件启动
./ping-agent config.json

# 查看版本
./ping-agent -v
```

## 📡 API 文档

### 探测接口

**POST** `/probe`

#### 请求头

| 参数            | 类型   | 必填 | 说明                                      |
| --------------- | ------ | ---- | ----------------------------------------- |
| `Authorization` | string |     | Bearer Token 认证，格式：`Bearer <token>` |

#### 请求体

| 参数     | 类型    | 必填   | 默认值 | 说明                         | 示例                     |
| -------- | ------- | ------ | ------ | ---------------------------- | ------------------------ |
| `target` | string  | **是** |       | 探测目标，支持域名或 IP 地址 | `example.com`、`8.8.8.8` |
| `port`   | integer |     | `22`   | TCP 探测端口，范围：1-65535  | `443`、`80`              |

#### 响应体

```json
[
  {
    "ip": "192.168.1.1",
    "icmp": 50.23,
    "tcp": 45.12
  },
  {
    "ip": "192.168.1.2",
    "icmp": 48.11,
    "tcp": 42.34
  }
]
```

## 🔧 生产部署

### Systemd 服务

创建 `/etc/systemd/system/ping-agent.service`：

```ini
[Unit]
Description=PingAgent Network Probe Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=/opt/ping-agent
ExecStart=/opt/ping-agent/ping-agent /opt/ping-agent/config.json
Restart=always
RestartSec=10
StandardOutput=append:/var/log/ping-agent.log
StandardError=append:/var/log/ping-agent.log

# 安全限制
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log

# ICMP权限
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

#### 管理命令

```bash
# 启动服务
sudo systemctl start ping-agent

# 开机自启
sudo systemctl enable ping-agent

# 查看状态
sudo systemctl status ping-agent

# 查看日志
sudo journalctl -u ping-agent -f
```

## 常见问题

1. `ping: socket: Operation not permitted`  
   → Linux 未赋 CAP_NET_RAW / 非 root；或 macOS 需 sudo。
2. `403 Forbidden (IP)` / `401 Unauthorized (Token)`  
   → 请求 IP 或 Token 不在白名单。
3. 域名解析变化后仍被拒绝  
   → 等待 5 min 缓存过期或重启 agent。

## License

PingAgent is an open-sourced software licensed under the GPL-3.0 license.
