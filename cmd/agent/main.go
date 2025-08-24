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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// 版本信息，由构建时注入
var Version = "dev"

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
	IPs        []string
	LastUpdate time.Time
}

/* ------------ 全局变量 ------------ */
var (
	conf         Config
	ipNetworks   []*net.IPNet
	soloIPs      sync.Map 
	domainCaches = sync.Map{}
	allowAll     bool
	dnsCache     = sync.Map{}
)

/* ------------ 常量 ------------ */
const (
	// 探测参数 - 关键优化点
	icmpCount   = 3                       // ICMP ping 次数
	tcpCount    = 3                       // TCP 连接次数
	probeTimeout = 1500 * time.Millisecond // 单次探测超时
	totalTimeout = 5 * time.Second         // 总超时时间
	
	// 缓存和后台任务
	dnsCacheTTL = 2 * time.Minute
	domainTTL   = 5 * time.Minute
	
	// 并发控制
	maxConcurrentProbes = 50 // 降低并发数，避免资源竞争
)

/* ---------- DNS 缓存结构 ---------- */
type dnsEntry struct {
	IP       string
	Expiry   time.Time
	Resolved bool
}

/* =============== 主函数 =============== */
func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("ping-agent %s\n", Version)
		return
	}

	if len(os.Args) < 2 {
		log.Fatal("Usage: ./ping-agent <config.json> Or ./ping-agent --version")
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	
	loadConfig(os.Args[1])
	buildWhiteList()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go domainRefreshWorker(ctx)
	go dnsCacheCleanup(ctx)

	probeSemaphore := make(chan struct{}, maxConcurrentProbes)
	
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r, probeSemaphore)
	})

	srv := &http.Server{
		Addr:              conf.HttpListen,
		Handler:           mux,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
		MaxHeaderBytes:    8192,
	}

	go func() {
		log.Printf("PingAgent Start! Listen %s", conf.HttpListen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP Service failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	log.Println("Closing Service...")
	
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Close failed: %v", err)
	}
}

/* =============== HTTP 处理器 =============== */
type httpReq struct {
	Target string `json:"target"`
	Port   int    `json:"port,omitempty"`
}

type httpResp struct {
	IP   string  `json:"ip"`
	ICMP float64 `json:"icmp"`
	TCP  float64 `json:"tcp"`
}

func probeHandler(w http.ResponseWriter, r *http.Request, semaphore chan struct{}) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Only Support POST Method")
		return
	}

	if !ipAllowed(extractClientIP(r)) {
		writeJSONError(w, http.StatusForbidden, "IP Not Allowed")
		return
	}
	if conf.Auth.Token != "" && extractBearerToken(r.Header.Get("Authorization")) != conf.Auth.Token {
		writeJSONError(w, http.StatusUnauthorized, "Authorization Token Invalid")
		return
	}

	// 并发控制
	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	default:
		writeJSONError(w, http.StatusTooManyRequests, "Too Many Requests")
		return
	}

	var req httpReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Target == "" {
		writeJSONError(w, http.StatusBadRequest, "Missing Target Parameter")
		return
	}

	if req.Port <= 0 {
		req.Port = 22
	} else if req.Port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "Invalid Port")
		return
	}

	// DNS 解析
	ip, err := resolveWithCache(req.Target)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "DNS Resolve Failed")
		return
	}

	// 使用 context 控制整体探测超时
	ctxProbe, cancel := context.WithTimeout(r.Context(), totalTimeout)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var icmpRTT, tcpRTT float64

	wg.Add(1)
	go func() {
		defer wg.Done()
		if v := probeICMPConcurrent(ctxProbe, ip); v > 0 {
			mu.Lock()
			icmpRTT = v
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if v := probeTCPConcurrent(ctxProbe, ip, req.Port); v > 0 {
			mu.Lock()
			tcpRTT = v
			mu.Unlock()
		}
	}()

	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(httpResp{IP: ip, ICMP: icmpRTT, TCP: tcpRTT})
}

/* =============== 并发探测函数 =============== */
func probeICMPConcurrent(ctx context.Context, host string) float64 {
	results := make(chan time.Duration, icmpCount)
	var wg sync.WaitGroup
	wg.Add(icmpCount)

	for i := 0; i < icmpCount; i++ {
		go func() {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			p, err := probing.NewPinger(host)
			if err != nil {
				return
			}
			p.Count = 1
			p.Timeout = probeTimeout

			p.SetPrivileged(true)
			if err = p.Run(); err != nil {
				p.SetPrivileged(false)
				if err = p.Run(); err != nil {
					return
				}
			}
			stats := p.Statistics()
			if stats.PacketsRecv > 0 {
				select {
				case results <- stats.AvgRtt:
				case <-ctx.Done():
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var total time.Duration
	var n int
	for {
		select {
		case <-ctx.Done():
			return 0
		case rtt, ok := <-results:
			if !ok {
				if n == 0 {
					return 0
				}
				return float64(total/time.Duration(n)) / 1e6
			}
			if rtt > 0 {
				total += rtt
				n++
			}
		}
	}
}

func probeTCPConcurrent(ctx context.Context, host string, port int) float64 {
    results := make(chan time.Duration, tcpCount)
    addr := fmt.Sprintf("%s:%d", host, port)
    var wg sync.WaitGroup

    for i := 0; i < tcpCount; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            select {
            case <-ctx.Done():
                return
            default:
            }
            start := time.Now()
            conn, err := net.DialTimeout("tcp", addr, probeTimeout)
            if err == nil {
                rtt := time.Since(start)
                conn.Close()
                select {
                case results <- rtt:
                case <-ctx.Done():
                }
            }
        }()
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    var validRTTs []time.Duration
    for {
        select {
        case <-ctx.Done():
            return 0
        case rtt, ok := <-results:
            if !ok {
                if len(validRTTs) == 0 {
                    return 0
                }
                var total time.Duration
                for _, v := range validRTTs {
                    total += v
                }
                return float64(total/time.Duration(len(validRTTs))) / 1e6
            }
            if rtt > 0 {
                validRTTs = append(validRTTs, rtt)
            }
        }
    }
}

/* =============== DNS 缓存 =============== */
func resolveWithCache(target string) (string, error) {
	// 检查是否已是 IP
	if ip := net.ParseIP(target); ip != nil {
		return ip.String(), nil
	}

	// 检查缓存
	if entry, ok := dnsCache.Load(target); ok {
		if e := entry.(dnsEntry); time.Now().Before(e.Expiry) {
			if e.Resolved {
				return e.IP, nil
			}
			return "", fmt.Errorf("DNS Resolution Failed")
		}
	}

	// 快速 DNS 解析
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil || len(ips) == 0 {
		// 缓存失败结果
		dnsCache.Store(target, dnsEntry{
			IP:       "",
			Expiry:   time.Now().Add(30 * time.Second),
			Resolved: false,
		})
		return "", err
	}

	// 优先选择 IPv4
	var selectedIP string
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			selectedIP = ip.IP.String()
			break
		}
	}
	if selectedIP == "" {
		selectedIP = ips[0].IP.String()
	}

	// 缓存成功结果
	dnsCache.Store(target, dnsEntry{
		IP:       selectedIP,
		Expiry:   time.Now().Add(dnsCacheTTL),
		Resolved: true,
	})

	return selectedIP, nil
}

/* =============== 权限检查 =============== */
func ipAllowed(ipStr string) bool {
	if allowAll {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ipS := ip.String()

	// 单 IP 检查 (sync.Map)
	if _, ok := soloIPs.Load(ipS); ok {
		return true
	}

	// 网络段检查
	for _, network := range ipNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	// 域名缓存检查
	found := false
	domainCaches.Range(func(_, value interface{}) bool {
		cache := value.(*domainCache)
		for _, cachedIP := range cache.IPs {
			if cachedIP == ipS {
				found = true
				return false
			}
		}
		return true
	})

	return found
}

/* =============== 后台任务 =============== */
func domainRefreshWorker(ctx context.Context) {
	ticker := time.NewTicker(domainTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			domainCaches.Range(func(key, value interface{}) bool {
				domain := key.(string)
				cache := value.(*domainCache)
				
				if time.Since(cache.LastUpdate) > domainTTL {
					go refreshDomainIP(domain)
				}
				return true
			})
		}
	}
}

func refreshDomainIP(domain string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		domainCaches.Delete(domain)
		return
	}

	ipStrings := make([]string, 0, len(ips))
	for _, ipa := range ips {
		ipStr := ipa.IP.String()
		ipStrings = append(ipStrings, ipStr)
		soloIPs.Store(ipStr, struct{}{})
	}

	domainCaches.Store(domain, &domainCache{
		IPs:        ipStrings,
		LastUpdate: time.Now(),
	})
}


func dnsCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			dnsCache.Range(func(key, value interface{}) bool {
				if entry := value.(dnsEntry); now.After(entry.Expiry) {
					dnsCache.Delete(key)
				}
				return true
			})
		}
	}
}

/* =============== 初始化函数 =============== */
func loadConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}
	
	if err := json.Unmarshal(data, &conf); err != nil {
		log.Fatalf("解析配置失败: %v", err)
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

	// 处理 IP 白名单
	for _, ipStr := range conf.Auth.AllowIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		if strings.Contains(ipStr, "/") {
			if _, network, err := net.ParseCIDR(ipStr); err == nil {
				ipNetworks = append(ipNetworks, network)
			}
		} else {
			if net.ParseIP(ipStr) != nil {
				soloIPs.Store(ipStr, struct{}{})
			}
		}
	}

	// 处理域名白名单：同步解析一次，避免并发写导致 race
	for _, domain := range conf.Auth.AllowDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		refreshDomainIP(domain)
	}
}

/* =============== 工具函数 =============== */
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func extractBearerToken(authHeader string) string {
	const prefix = "Bearer "
	if strings.HasPrefix(authHeader, prefix) {
		return authHeader[len(prefix):]
	}
	return ""
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}