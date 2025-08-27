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

var Version = "dev"

type Config struct {
	HttpListen string `json:"http_listen"`
	Auth       struct {
		Token        string   `json:"token"`
		AllowIPs     []string `json:"allow_ips"`
		AllowDomains []string `json:"allow_domains"`
	} `json:"auth"`
}

type ProbeResult struct {
	IP   string  `json:"ip"`
	ICMP float64 `json:"icmp"`
	TCP  float64 `json:"tcp"`
}

var (
	cfg          Config
	cache        sync.Map // 统一缓存: key -> (value, expiry)
	ipNetworks   []*net.IPNet
	staticIPs    map[string]bool
	allowAll     bool
	probeLimiter chan struct{}
	tcpDialer    = &net.Dialer{Timeout: 1500 * time.Millisecond}
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		fmt.Printf("ping-agent %s\n", Version)
		return
	}
	if len(os.Args) < 2 {
		log.Fatal("Usage: ./ping-agent <config.json>")
	}
	// 初始化
	loadConfig(os.Args[1])
	initWhitelist()
	probeLimiter = make(chan struct{}, 50)
	// 缓存清理
	go func() {
		for range time.Tick(5 * time.Minute) {
			cache.Range(func(k, v interface{}) bool {
				if time.Now().After(v.(*cacheItem).expiry) {
					cache.Delete(k)
				}
				return true
			})
		}
	}()
	// HTTP服务
	http.HandleFunc("/probe", handleProbe)
	srv := &http.Server{Addr: cfg.HttpListen, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		log.Printf("PingAgent Start! Listen %s", cfg.HttpListen)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	// 优雅关闭
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func loadConfig(path string) {
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &cfg)
	if cfg.HttpListen == "" {
		cfg.HttpListen = ":8080"
	}
}

func initWhitelist() {
	if len(cfg.Auth.AllowIPs) == 0 && len(cfg.Auth.AllowDomains) == 0 {
		allowAll = true
		return
	}
	staticIPs = make(map[string]bool)

	for _, ip := range cfg.Auth.AllowIPs {
		ip = strings.TrimSpace(ip)
		if strings.Contains(ip, "/") {
			if _, n, err := net.ParseCIDR(ip); err == nil {
				ipNetworks = append(ipNetworks, n)
			}
		} else if net.ParseIP(ip) != nil {
			staticIPs[ip] = true
		}
	}
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	// 基础检查
	if r.Method != "POST" {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// IP权限
	if !isAllowed(getClientIP(r)) {
		http.Error(w, `{"error":"Forbidden"}`, http.StatusForbidden)
		return
	}
	// Token验证
	if cfg.Auth.Token != "" && r.Header.Get("Authorization") != "Bearer "+cfg.Auth.Token {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	// 限流
	select {
	case probeLimiter <- struct{}{}:
		defer func() { <-probeLimiter }()
	default:
		http.Error(w, `{"error":"Too many requests"}`, http.StatusTooManyRequests)
		return
	}
	// 解析请求
	var req struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Target == "" {
		http.Error(w, `{"error":"Bad request"}`, http.StatusBadRequest)
		return
	}
	if req.Port <= 0 {
		req.Port = 22
	} else if req.Port > 65535 {
		http.Error(w, `{"error":"Invalid Port"}`, http.StatusBadRequest)
		return
	}
	// 执行探测
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(probe(ctx, req.Target, req.Port))
}

// 解析域名，返回所有IP字符串
func resolveDomain(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP.String())
	}
	return ips, nil
}

func domainIPsToMap(domain string) (map[string]bool, error) {
	ips, err := resolveDomain(domain)
	if err != nil {
		return map[string]bool{}, err
	}
	m := make(map[string]bool)
	for _, addr := range ips {
		m[addr] = true
	}
	return m, nil
}

func isAllowed(ip string) bool {
	if allowAll {
		return true
	}
	// 检查静态IP
	if staticIPs[ip] {
		return true
	}
	// 检查CIDR
	if parsed := net.ParseIP(ip); parsed != nil {
		for _, n := range ipNetworks {
			if n.Contains(parsed) {
				return true
			}
		}
	}
	// 检查域名（带缓存）
	for _, domain := range cfg.Auth.AllowDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		// 第一次尝试：从缓存获取
		cacheKey := "_domain:" + domain

		// 统一使用getOrResolve处理缓存
		ips, _ := getOrResolve(cacheKey, func() (interface{}, error) {
			return domainIPsToMap(domain)
		}, 24*time.Hour)

		if ips.(map[string]bool)[ip] {
			return true
		}

		// IP不在缓存中，且超过5分钟，触发更新
		if _, recent := getCache(cacheKey + ":checked"); !recent {
			setCache(cacheKey+":checked", true, 5*time.Minute)
			// 异步更新缓存
			go func(d string) {
				m, err := domainIPsToMap(d)
				if err == nil && len(m) > 0 {
					setCache(cacheKey, m, 24*time.Hour)
				}
			}(domain)
		}
	}

	return false
}

func probe(ctx context.Context, target string, port int) []ProbeResult {
	// 解析目标
	ips := []string{}
	if ip := net.ParseIP(target); ip != nil {
		ips = []string{target}
	} else {
		// DNS解析（带缓存）
		if v, _ := getOrResolve("_dns:"+target, func() (interface{}, error) {
			allIPs, err := resolveDomain(target)
			if err != nil {
				return []string{}, err
			}
			result := make([]string, 0, min(len(allIPs), 10))
			for _, ip := range allIPs {
				result = append(result, ip)
				if len(result) >= 10 { // 限制最大IP数
					break
				}
			}
			return result, nil
		}, 5*time.Minute); v != nil {
			ips = v.([]string)
		}
	}
	if len(ips) == 0 {
		return nil
	}
	// 并发探测所有IP
	results := make([]ProbeResult, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()
			ch := make(chan float64, 2)
			go func() { ch <- probeICMP(ctx, ip) }()
			go func() { ch <- probeTCP(ctx, ip, port) }()
			results[idx] = ProbeResult{
				IP:   ip,
				ICMP: <-ch,
				TCP:  <-ch,
			}
		}(i, ip)
	}
	wg.Wait()
	return results
}

// 通用并发探测函数
func probeN(ctx context.Context, n int, probeFn func() (time.Duration, bool)) float64 {
	ch := make(chan time.Duration, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, ok := probeFn(); ok {
				select {
				case ch <- d:
				case <-ctx.Done():
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	// 收集结果
	var total time.Duration
	var count int
	for d := range ch {
		total += d
		count++
	}
	if count == 0 {
		return 0
	}
	return float64(total/time.Duration(count)) / 1e6
}

func probeICMP(ctx context.Context, host string) float64 {
	return probeN(ctx, 3, func() (time.Duration, bool) {
		pinger, err := probing.NewPinger(host)
		if err != nil {
			return 0, false
		}
		pinger.Count = 1
		pinger.Timeout = 1500 * time.Millisecond
		pinger.SetPrivileged(true)
		if err := pinger.Run(); err != nil {
			pinger.SetPrivileged(false)
			if err := pinger.Run(); err != nil {
				return 0, false
			}
		}
		if s := pinger.Statistics(); s.PacketsRecv > 0 {
			return s.AvgRtt, true
		}
		return 0, false
	})
}

func probeTCP(ctx context.Context, host string, port int) float64 {
	addr := fmt.Sprintf("%s:%d", host, port)
	return probeN(ctx, 3, func() (time.Duration, bool) {
		start := time.Now()
		if conn, err := tcpDialer.DialContext(ctx, "tcp", addr); err == nil {
			conn.Close()
			return time.Since(start), true
		}
		return 0, false
	})
}

// ============ 工具函数 ============
type cacheItem struct {
	value  interface{}
	expiry time.Time
}

func getCache(key string) (interface{}, bool) {
	if v, ok := cache.Load(key); ok {
		if item := v.(*cacheItem); time.Now().Before(item.expiry) {
			return item.value, true
		}
		cache.Delete(key)
	}
	return nil, false
}

func setCache(key string, value interface{}, ttl time.Duration) {
	cache.Store(key, &cacheItem{value: value, expiry: time.Now().Add(ttl)})
}

func getOrResolve(key string, resolve func() (interface{}, error), ttl time.Duration) (interface{}, error) {
	if v, ok := getCache(key); ok {
		return v, nil
	}
	v, err := resolve()
	if err == nil {
		setCache(key, v, ttl)
	}
	return v, err
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if i := strings.Index(ip, ","); i > 0 {
			return strings.TrimSpace(ip[:i])
		}
		return strings.TrimSpace(ip)
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
