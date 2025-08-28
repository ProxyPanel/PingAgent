package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var Version = "dev"

// 配置结构
type Config struct {
	HttpListen string `json:"http_listen"`
	Auth       struct {
		Token        string   `json:"token"`
		AllowIPs     []string `json:"allow_ips"`
		AllowDomains []string `json:"allow_domains"`
	} `json:"auth"`
}

// 探测结果
type ProbeResult struct {
	IP   string  `json:"ip"`
	ICMP float64 `json:"icmp"`
	TCP  float64 `json:"tcp"`
}

// 缓存项
type cacheItem struct {
	value  interface{}
	expiry time.Time
}

// 白名单管理器
type WhitelistManager struct {
	mu           sync.RWMutex
	ipNetworks   []*net.IPNet
	staticIPs    map[string]bool
	allowAll     bool
	allowDomains []string
}

var (
	cfg              Config
	cache            sync.Map
	whitelistManager *WhitelistManager
	probeLimiter     chan struct{}
	tcpDialer        = &net.Dialer{Timeout: 1500 * time.Millisecond}
)

const (
	defaultHTTPPort     = ":8080"
	defaultProbePort    = 22
	maxConcurrentProbes = 50
	maxIPsPerDomain     = 10
	cacheTTL            = 5 * time.Minute
	domainCacheTTL      = 24 * time.Hour
	probeTimeout        = 5 * time.Second
	pingTimeout         = 1500 * time.Millisecond
	cacheCleanInterval  = 5 * time.Minute
	probeSamples        = 3 // 每次探测的采样数
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
	if err := loadConfig(os.Args[1]); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	whitelistManager = initWhitelist()
	probeLimiter = make(chan struct{}, maxConcurrentProbes)

	// 启动缓存清理
	stopCacheCleaner := startCacheCleaner()
	defer stopCacheCleaner()

	// 启动HTTP服务
	srv := startHTTPServer()

	// 优雅关闭
	waitForShutdown(srv)
}

// 加载配置文件
func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if cfg.HttpListen == "" {
		cfg.HttpListen = defaultHTTPPort
	}

	return nil
}

// 初始化白名单
func initWhitelist() *WhitelistManager {
	wm := &WhitelistManager{
		staticIPs:    make(map[string]bool),
		allowDomains: cfg.Auth.AllowDomains,
	}

	if len(cfg.Auth.AllowIPs) == 0 && len(cfg.Auth.AllowDomains) == 0 {
		wm.allowAll = true
		return wm
	}

	for _, ip := range cfg.Auth.AllowIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		if strings.Contains(ip, "/") {
			if _, n, err := net.ParseCIDR(ip); err == nil {
				wm.ipNetworks = append(wm.ipNetworks, n)
			} else {
				log.Printf("Invalid CIDR: %s", ip)
			}
		} else if net.ParseIP(ip) != nil {
			wm.staticIPs[ip] = true
		} else {
			log.Printf("Invalid IP: %s", ip)
		}
	}

	return wm
}

// 启动缓存清理器
func startCacheCleaner() func() {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		ticker := time.NewTicker(cacheCleanInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cleanExpiredCache()
			case <-ctx.Done():
				return
			}
		}
	}()

	return cancel
}

// 清理过期缓存
func cleanExpiredCache() {
	now := time.Now()
	var cleaned int

	cache.Range(func(k, v interface{}) bool {
		if item, ok := v.(*cacheItem); ok && now.After(item.expiry) {
			cache.Delete(k)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		log.Printf("Cleaned %d expired cache entries", cleaned)
	}
}

// 启动HTTP服务器
func startHTTPServer() *http.Server {
	http.HandleFunc("/probe", handleProbe)

	srv := &http.Server{
		Addr:         cfg.HttpListen,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("PingAgent %s started on %s", Version, cfg.HttpListen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	return srv
}

// 等待关闭信号
func waitForShutdown(srv *http.Server) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}

// 处理探测请求
func handleProbe(w http.ResponseWriter, r *http.Request) {
	// 请求验证
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 关闭请求体
	defer r.Body.Close()

	// IP权限检查
	clientIP := getClientIP(r)
	if !whitelistManager.isAllowed(clientIP) {
		writeJSONError(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Token验证
	if cfg.Auth.Token != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || auth[7:] != cfg.Auth.Token {
			writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 限流
	select {
	case probeLimiter <- struct{}{}:
		defer func() { <-probeLimiter }()
	default:
		writeJSONError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// 解析请求
	var req struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
	}

	// 限制请求体大小
	limitedReader := io.LimitReader(r.Body, 1024*1024) // 1MB
	if err := json.NewDecoder(limitedReader).Decode(&req); err != nil || req.Target == "" {
		writeJSONError(w, "Bad request", http.StatusBadRequest)
		return
	}

	// 验证端口
	if req.Port == 0 {
		req.Port = defaultProbePort
	} else if req.Port < 1 || req.Port > 65535 {
		writeJSONError(w, "Invalid port", http.StatusBadRequest)
		return
	}

	// 执行探测
	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	results := probe(ctx, req.Target, req.Port)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// 检查IP是否允许
func (wm *WhitelistManager) isAllowed(ip string) bool {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if wm.allowAll {
		return true
	}

	// 检查静态IP
	if wm.staticIPs[ip] {
		return true
	}

	// 检查CIDR
	if parsed := net.ParseIP(ip); parsed != nil {
		for _, n := range wm.ipNetworks {
			if n.Contains(parsed) {
				return true
			}
		}
	}

	// 检查域名
	return wm.checkDomainIP(ip)
}

// 检查IP是否属于允许的域名
func (wm *WhitelistManager) checkDomainIP(ip string) bool {
	for _, domain := range wm.allowDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		cacheKey := "_domain:" + domain
		ips, err := getOrResolve(cacheKey, func() (interface{}, error) {
			return domainIPsToMap(domain)
		}, domainCacheTTL)

		if err == nil && ips != nil {
			if ipMap, ok := ips.(map[string]bool); ok && ipMap[ip] {
				return true
			}
		}

		// 触发异步更新
		updateKey := cacheKey + ":updating"
		if _, recent := getCache(updateKey); !recent {
			setCache(updateKey, true, 5*time.Minute)
			go wm.updateDomainCache(domain, cacheKey)
		}
	}

	return false
}

// 异步更新域名缓存
func (wm *WhitelistManager) updateDomainCache(domain, cacheKey string) {
	m, err := domainIPsToMap(domain)
	if err == nil && len(m) > 0 {
		setCache(cacheKey, m, domainCacheTTL)
		log.Printf("Updated domain cache for %s: %d IPs", domain, len(m))
	}
}

// 执行探测
func probe(ctx context.Context, target string, port int) []ProbeResult {
	ips := resolveTarget(ctx, target)
	if len(ips) == 0 {
		return nil
	}

	results := make([]ProbeResult, len(ips))
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()

			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			result := ProbeResult{IP: ip}

			// 使用channel确保ICMP和TCP并发
			icmpChan := make(chan float64, 1)
			tcpChan := make(chan float64, 1)

			// ICMP并发执行
			go func() {
				icmpChan <- probeICMP(probeCtx, ip)
			}()

			// TCP并发执行
			go func() {
				tcpChan <- probeTCP(probeCtx, ip, port)
			}()

			// 等待两个结果
			result.ICMP = <-icmpChan
			result.TCP = <-tcpChan

			results[idx] = result
		}(i, ip)
	}

	wg.Wait()
	return results
}

// 解析目标地址
func resolveTarget(ctx context.Context, target string) []string {
	// 直接IP地址
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}
	}

	// DNS解析（带缓存）
	cacheKey := "_dns:" + target
	v, err := getOrResolve(cacheKey, func() (interface{}, error) {
		return resolveDomain(target)
	}, cacheTTL)

	if err != nil || v == nil {
		return nil
	}

	if ips, ok := v.([]string); ok {
		return ips
	}

	return nil
}

// 解析域名
func resolveDomain(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}

	// 限制返回的IP数量
	maxIPs := min(len(addrs), maxIPsPerDomain)
	ips := make([]string, 0, maxIPs)

	for i := 0; i < maxIPs; i++ {
		ips = append(ips, addrs[i].IP.String())
	}

	return ips, nil
}

// 将域名解析为IP映射
func domainIPsToMap(domain string) (map[string]bool, error) {
	ips, err := resolveDomain(domain)
	if err != nil {
		return nil, err
	}

	m := make(map[string]bool, len(ips))
	for _, ip := range ips {
		m[ip] = true
	}

	return m, nil
}

// 原生ICMP探测实现
func probeICMP(ctx context.Context, host string) float64 {
	// 解析目标地址
	dst, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return 0
	}

	// 根据IP版本选择协议
	var network string
	var proto int
	if dst.IP.To4() != nil {
		network = "ip4:icmp"
		proto = 1 // ICMP for IPv4
	} else {
		network = "ip6:ipv6-icmp"
		proto = 58 // ICMPv6
	}

	// 创建ICMP连接
	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		// 如果需要root权限失败，尝试非特权模式
		if network == "ip4:icmp" {
			conn, err = icmp.ListenPacket("udp4", "")
		} else {
			conn, err = icmp.ListenPacket("udp6", "")
		}
		if err != nil {
			return 0
		}
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetDeadline(time.Now().Add(pingTimeout))

	// 收集多次探测结果
	durations := collectICMPSamples(ctx, conn, dst, proto, probeSamples)
	if len(durations) == 0 {
		return 0
	}

	return calculateAverage(durations)
}

// 收集ICMP采样数据
func collectICMPSamples(ctx context.Context, conn *icmp.PacketConn, dst *net.IPAddr, proto int, samples int) []time.Duration {
	type result struct {
		duration time.Duration
		success  bool
	}

	resultChan := make(chan result, samples)

	// 并发发送多个ping包
	for i := 0; i < samples; i++ {
		go func(seq int) {
			duration := sendICMPPacket(conn, dst, proto, seq)
			resultChan <- result{duration, duration > 0}
		}(i)
	}

	// 收集结果
	var validResults []time.Duration
	for i := 0; i < samples; i++ {
		select {
		case r := <-resultChan:
			if r.success {
				validResults = append(validResults, r.duration)
			}
		case <-ctx.Done():
			return validResults
		}
	}

	return validResults
}

// 发送单个ICMP包并等待响应
func sendICMPPacket(conn *icmp.PacketConn, dst *net.IPAddr, proto int, seq int) time.Duration {
	// 构造ICMP包
	var icmpType icmp.Type
	if dst.IP.To4() != nil {
		icmpType = ipv4.ICMPTypeEcho
	} else {
		icmpType = ipv6.ICMPTypeEchoRequest
	}

	message := &icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: []byte("ping"),
		},
	}

	data, err := message.Marshal(nil)
	if err != nil {
		return 0
	}

	// 发送包
	start := time.Now()
	_, err = conn.WriteTo(data, dst)
	if err != nil {
		return 0
	}

	// 接收响应
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return 0
	}
	duration := time.Since(start)

	// 验证响应
	replyMsg, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return 0
	}

	// 检查响应类型
	var isEchoReply bool
	if dst.IP.To4() != nil {
		isEchoReply = replyMsg.Type == ipv4.ICMPTypeEchoReply
	} else {
		isEchoReply = replyMsg.Type == ipv6.ICMPTypeEchoReply
	}

	if isEchoReply {
		if echo, ok := replyMsg.Body.(*icmp.Echo); ok {
			if echo.ID == os.Getpid()&0xffff && echo.Seq == seq {
				return duration
			}
		}
	}

	return 0
}

// TCP探测
func probeTCP(ctx context.Context, host string, port int) float64 {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	durations := collectTCPSamples(ctx, addr, probeSamples)
	if len(durations) == 0 {
		return 0
	}

	return calculateAverage(durations)
}

// 收集TCP采样数据
func collectTCPSamples(ctx context.Context, addr string, samples int) []time.Duration {
	type result struct {
		duration time.Duration
		success  bool
	}

	resultChan := make(chan result, samples)

	// 并发进行多次TCP连接
	for i := 0; i < samples; i++ {
		go func() {
			start := time.Now()
			conn, err := tcpDialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				resultChan <- result{time.Since(start), true}
			} else {
				resultChan <- result{0, false}
			}
		}()
	}

	// 收集结果
	var validResults []time.Duration
	for i := 0; i < samples; i++ {
		select {
		case r := <-resultChan:
			if r.success {
				validResults = append(validResults, r.duration)
			}
		case <-ctx.Done():
			return validResults
		}
	}

	return validResults
}

// 计算平均值（毫秒）
func calculateAverage(durations []time.Duration) float64 {
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return float64(total/time.Duration(len(durations))) / 1e6
}

/*============ 缓存管理 ============*/
// 设置缓存
func setCache(key string, value interface{}, ttl time.Duration) {
	cache.Store(key, &cacheItem{
		value:  value,
		expiry: time.Now().Add(ttl),
	})
}

// 获取缓存
func getCache(key string) (interface{}, bool) {
	if v, ok := cache.Load(key); ok {
		if item := v.(*cacheItem); time.Now().Before(item.expiry) {
			return item.value, true
		}
		cache.Delete(key)
	}
	return nil, false
}

// 获取或解析
func getOrResolve(key string, resolve func() (interface{}, error), ttl time.Duration) (interface{}, error) {
	if v, ok := getCache(key); ok {
		return v, nil
	}

	v, err := resolve()
	if err == nil && v != nil {
		setCache(key, v, ttl)
	}

	return v, err
}

/*============ 工具函数 ============*/
// 获取客户端IP
func getClientIP(r *http.Request) string {
	// X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}

	// X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

// 写入JSON错误响应
func writeJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":"%s"}`, message)
}
