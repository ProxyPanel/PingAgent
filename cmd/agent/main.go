package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

/* ------------ 配置 ------------ */
type Config struct {
	HttpListen string `json:"http_listen"`
	Auth       struct {
		Token        string   `json:"token"`
		AllowIPs     []string `json:"allow_ips"`
		AllowDomains []string `json:"allow_domains"`
	} `json:"auth"`
}

/* ---------- 白名单缓存 ---------- */
type domainCache struct {
	IPs        []net.IP
	LastUpdate time.Time
}

/* ------------ 全局 ------------ */
var (
	conf         Config
	ipNetworks   []*net.IPNet
	soloIPs      map[string]struct{}
	domainCaches = map[string]*domainCache{}
	mu           sync.RWMutex
	allowAll     bool

	dialer = net.Dialer{Timeout: timeout}
)

/* ------------ 常量 ------------ */
const (
	timeout   = 10 * time.Second
	pingCount = 3
	domainTTL = 5 * time.Minute
)

/* =============== 主函数 =============== */
func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: ./ping-agent <config.json>")
		os.Exit(1)
	}
	loadConfig(os.Args[1])
	buildWhiteList()

	mux := http.NewServeMux()
	mux.HandleFunc("/probe", httpHandler)

	srv := &http.Server{
		Addr:         conf.HttpListen,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("PingAgent HTTP 监听 %s", conf.HttpListen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}

	// 2. 等待 Ctrl-C / kill
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("收到退出信号, 正在关闭 HTTP 服务器...")

	// 3. 优雅关闭（给 5 秒处理正在运行的请求）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("HTTP 服务器关闭出错: %v", err)
	}
	log.Println("HTTP 服务器已关闭, 程序退出")
}

/* =============== HTTP =============== */
type httpReq struct {
	Target string `json:"target"`
	Port   int    `json:"port,omitempty"` // 可省略
}
type httpResp struct {
	IP   string  `json:"ip"`
	ICMP float64 `json:"icmp"`
	TCP  float64 `json:"tcp"`
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	if !ipAllowed(realIP(r)) {
		writeJSONError(w, http.StatusForbidden, "forbidden ip")
		return
	}
	if conf.Auth.Token != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got != conf.Auth.Token {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized token")
			return
		}
	}

	var req httpReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad json")
		return
	}

	if req.Target == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid param")
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "invalid port")
		return
	}

	ip, err := resolveTarget(req.Target)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "dns fail")
		return
	}

	icmpRTT := probeICMP(ip)
	tcpRTT := probeTCP(ip, func() int {
		if req.Port > 0 {
			return req.Port
		}
		return 22
	}())

	_ = json.NewEncoder(w).Encode(httpResp{IP: ip, ICMP: icmpRTT, TCP: tcpRTT})
}

/* =============== 探测 =============== */
func probeICMP(host string) float64 {
	p, err := probing.NewPinger(host)
	if err != nil {
		return 0
	}
	p.Count = pingCount
	p.Timeout = timeout
	p.SetPrivileged(true)
	if err = p.Run(); err != nil {
		p.SetPrivileged(false)
		if err = p.Run(); err != nil {
			return 0
		}
	}
	s := p.Statistics()
	if s.PacketsRecv > 0 {
		return float64(s.AvgRtt.Microseconds()) / 1000
	}
	return 0
}

func probeTCP(host string, port int) float64 {
	start := time.Now()
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return 0
	}
	_ = conn.Close()
	return float64(time.Since(start).Microseconds()) / 1000
}

/* =============== 白名单 =============== */
func ipAllowed(ipStr string) bool {
	if allowAll {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	mu.RLock()
	if _, ok := soloIPs[ip.String()]; ok {
		mu.RUnlock()
		return true
	}
	for _, nw := range ipNetworks {
		if nw.Contains(ip) {
			mu.RUnlock()
			return true
		}
	}
	needRefresh := false
	for _, c := range domainCaches {
		if time.Since(c.LastUpdate) > domainTTL {
			needRefresh = true
			break
		}
	}
	mu.RUnlock()

	if needRefresh {
		refreshDomains()
		mu.RLock()
		if _, ok := soloIPs[ip.String()]; ok {
			mu.RUnlock()
			return true
		}
		for _, nw := range ipNetworks {
			if nw.Contains(ip) {
				mu.RUnlock()
				return true
			}
		}
		mu.RUnlock()
	}
	return false
}

func refreshDomains() {
	mu.Lock()
	defer mu.Unlock()
	for d, c := range domainCaches {
		if time.Since(c.LastUpdate) <= domainTTL {
			continue
		}
		ips, err := net.LookupIP(d)
		if err != nil || len(ips) == 0 {
			continue
		}
		for _, old := range c.IPs {
			delete(soloIPs, old.String())
		}
		for _, ip := range ips {
			soloIPs[ip.String()] = struct{}{}
		}
		domainCaches[d] = &domainCache{IPs: ips, LastUpdate: time.Now()}
		log.Printf("[WhiteList] %s refreshed: %v", d, ips)
	}
}

/* =============== 初始化 =============== */
func loadConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if conf.HttpListen == "" {
		conf.HttpListen = ":8080"
	}
}

func buildWhiteList() {
	if len(conf.Auth.AllowIPs) == 0 && len(conf.Auth.AllowDomains) == 0 {
		allowAll = true
		return
	}

	soloIPs = make(map[string]struct{})
	for _, v := range conf.Auth.AllowIPs {
		if strings.Contains(v, "/") {
			if _, nw, err := net.ParseCIDR(v); err == nil {
				ipNetworks = append(ipNetworks, nw)
			}
		} else {
			soloIPs[v] = struct{}{}
		}
	}
	for _, d := range conf.Auth.AllowDomains {
		ips, _ := net.LookupIP(d)
		domainCaches[d] = &domainCache{IPs: ips, LastUpdate: time.Now()}
		for _, ip := range ips {
			soloIPs[ip.String()] = struct{}{}
		}
	}
}

/* =============== 工具函数 =============== */
func resolveTarget(t string) (string, error) {
	if net.ParseIP(t) != nil {
		return t, nil
	}
	ips, err := net.LookupIP(t)
	if err != nil || len(ips) == 0 {
		return "", err
	}
	return ips[0].String(), nil
}

func realIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	if v := r.Header.Get("X-Real-Ip"); v != "" {
		return v
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

/* =============== JSON Error Helper =============== */
type jsonErr struct {
	Error string `json:"error"`
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonErr{Error: msg})
}
