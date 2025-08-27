# PingAgent
轻量级网络连通性探测器 / 多节点主动监控组件

Lightweight Network Probe for Multi-Node Active Monitoring

---


## 1. 功能概述

• HTTP/JSON 接口 `/probe`，返回 ICMP ping + TCP 连接 RTT  
• 外部 `config.json` 热插拔部署，支持  
 ‑ 监听端口 (`http_listen`)  
 ‑ Bearer-Token 鉴权  
 ‑ IP / CIDR / 域名白名单  
• 域名白名单 **懒刷新**：仅当缓存超时(默认 5 min)且出现未命中时再解析 DNS  
• ICMP：发送 3 包，若无 CAP_NET_RAW 自动回退 UDP ping  
• HTTP Server 带 Read/Write/Idle 超时，防慢速攻击  
• 单文件编译，体积 < 5 MB


### 快速部署
#### 安装
```sh
curl -sSfL https://raw.githubusercontent.com/ProxyPanel/PingAgent/main/ping-agent.sh | \
bash -s -- install \
  --token 123456 \
  --listen ":8080" \
  --allow-ips "127.0.0.1,10.0.0.0/8" \
  --allow-domains "control.example.com" \
  --version latest
```


#### 更新
```sh
# 默认是最新版本
./ping-agent.sh update

# 指定版本
./ping-agent.sh update v1.2.3
```

#### 卸载
```sh
./ping-agent.sh uninstall
```

## 2. 目录结构

```
ping-agent/
├─ go.mod                 # 依赖声明
├─ config.sample.json     # 配置示例
└─ cmd/
   └─ agent/
       └─ main.go         # 源码
```


## 3. 运行环境

1. Go 1.24+
2. （Linux）给予二进制 ICMP 权限
   ```
   sudo setcap cap_net_raw+ep ./ping-agent
   ```
   或者直接 root 运行。
3. macOS 无法 setcap；如需 ICMP，请 sudo 运行或放弃 ICMP（代码自动降级 UDP）。


## 4. 依赖

go.mod 仅 1 个第三方库

```
github.com/prometheus-community/pro-bing v0.11.0
```


## 5. 编译步骤

```bash
git clone https://github.com/ProxyPanel/PingAgent.git
cd PingAgent
go mod tidy                              # 拉取依赖
go build -o ping-agent ./cmd/agent      # 生成二进制
sudo setcap cap_net_raw+ep ./ping-agent # (Linux) 给予 ICMP 权限
```

## 6. 配置文件

`config.sample.json`

```json
{
  "http_listen": ":8080",
  "auth": {
    "token": "ChangeMeIfNeeded",
    "allow_ips": ["127.0.0.1", "::1"],
    "allow_domains": ["control.example.com"]
  }
}
```

解释  
• http_listen – HTTP 监听地址，默认 `:8080`  
• token – Bearer 鉴权；留空则不校验  
• allow_ips – 源 IP / CIDR 白名单  
• allow_domains – 源域名白名单，懒解析为 IP，缓存 5 min


## 7. 启动

```bash
./ping-agent config.json
# 输出:
# PingAgent Start! Listen :8080
```

Systemd 示例

```
[Unit]
Description=Probe Agent
After=network.target

[Service]
ExecStart=/opt/ping-agent/ping-agent /opt/ping-agent/config.json
AmbientCapabilities=CAP_NET_RAW
Restart=on-failure

[Install]
WantedBy=multi-user.target
```


## 8. 调用示例

### curl

```bash
curl -X POST http://127.0.0.1:8080/probe \
     -H "Authorization: Bearer ChangeMeIfNeeded" \
     -H "Content-Type: application/json" \
     -d '{"target":"bing.com","port":443}'
```

### Laravel

```php
$data = Http::withHeaders([
            'Authorization' => 'Bearer ChangeMeIfNeeded',
        ])->post('http://127.0.0.1:8080/probe', [
            'target' => 'bing.com',
            'port'   => 443,
        ])->json();
```

### Postman

1. Method: POST
2. URL: `http://127.0.0.1:8080/probe`
3. Header: `Authorization: Bearer ChangeMeIfNeeded`
4. Body (raw-JSON): `{"target":"bing.com","port":443}`


### 返回

```json
[
    {
        "ip": "2620:1ec:33::10",
        "icmp": 0,
        "tcp": 0
    },
    {
        "ip": "2620:1ec:33:1::10",
        "icmp": 0,
        "tcp": 0
    },
    {
        "ip": "150.171.28.10",
        "icmp": 50.2911,
        "tcp": 64.6117
    },
    {
        "ip": "150.171.27.10",
        "icmp": 58.1929,
        "tcp": 40.829933
    }
]
```


## 9. 懒刷新白名单工作流

1. Agent 启动时解析 `allow_domains` → 缓存 IP 集合，记录时间戳。
2. 收到请求 → 先用缓存匹配 IP → 匹配失败：  
   • 若距离上次解析 < 5 min，直接拒绝。  
   • 若已过 5 min，则即时解析域名、更新缓存，再判定一次。
3. 整个过程仅在「白名单过期 + 首次未命中」时触发 DNS 查询，避免无意义轮询。


## 10. 常见问题

1. `ping: socket: Operation not permitted`  
   → Linux 未赋 CAP_NET_RAW / 非 root；或 macOS 需 sudo。
2. `403 Forbidden (IP)` / `401 Unauthorized (Token)`  
   → 请求 IP 或 Token 不在白名单。
3. 域名解析变化后仍被拒绝  
   → 等待 5 min 缓存过期或重启 agent。


## 11. 性能 & 安全

• ICMP + TCP 单测 < 3 ms CPU 开销，同机器高并发 2 w rps 不成问题。  
• HTTP 超时 & 白名单双层拦截，减少慢速攻击面。  
• 若对安全要求更高：  
 ‑ 使用防火墙仅打开 8080，限制来源网段。  
 ‑ 将 HTTP 切换为 HTTPS+TLS 终端（nginx / caddy）。


## 12. License  
PingAgent is an open-sourced software licensed under the GPL-3.0 license.