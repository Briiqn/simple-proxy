package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/hashicorp/golang-lru/v2"
	"github.com/pquerna/cachecontrol"
	"golang.org/x/net/http2"
	"golang.org/x/sync/semaphore"
)

var (
	androidUserAgents = []string{
		"Mozilla/5.0 (Linux; Android 12; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	}

	iosUserAgents = []string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
	}

	windowsUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Edge/112.0.1722.64",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
	}

	macUserAgents = []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13.3; rv:109.0) Gecko/20100101 Firefox/112.0",
	}
)

type HeaderAnonymizer struct {
	rng *rand.Rand
}

func NewHeaderAnonymizer() *HeaderAnonymizer {
	return &HeaderAnonymizer{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (ha *HeaderAnonymizer) getRandomUserAgent(originalUA string) string {
	originalUA = strings.ToLower(originalUA)

	switch {
	case strings.Contains(originalUA, "android"):
		return androidUserAgents[ha.rng.Intn(len(androidUserAgents))]
	case strings.Contains(originalUA, "iphone") || strings.Contains(originalUA, "ipad") || strings.Contains(originalUA, "ios"):
		return iosUserAgents[ha.rng.Intn(len(iosUserAgents))]
	case strings.Contains(originalUA, "windows"):
		return windowsUserAgents[ha.rng.Intn(len(windowsUserAgents))]
	case strings.Contains(originalUA, "macintosh") || strings.Contains(originalUA, "mac os"):
		return macUserAgents[ha.rng.Intn(len(macUserAgents))]
	default:
		return windowsUserAgents[ha.rng.Intn(len(windowsUserAgents))]
	}
}

func (ha *HeaderAnonymizer) anonymizeHeaders(headers http.Header) http.Header {
	cleaned := make(http.Header)

	for key, values := range headers {
		key = strings.ToLower(key)

		switch key {
		case "cookie", "x-forwarded-for", "forwarded", "via", "referer", "origin",
			"true-client-ip", "x-real-ip", "cf-connecting-ip", "fastly-client-ip",
			"x-bb-ip", "x-client-ip", "x-cluster-client-ip", "x-forwarded",
			"x-forwarded-host", "x-fingerprint", "x-device-id":
			continue
		case "user-agent":
			if len(values) > 0 {
				cleaned.Set("User-Agent", ha.getRandomUserAgent(values[0]))
			}
			continue
		}

		for _, value := range values {
			cleaned.Add(key, value)
		}
	}

	cleaned.Set("Accept", "*/*")
	cleaned.Set("Accept-Language", "en-US,en;q=0.9")
	cleaned.Set("Accept-Encoding", "gzip, deflate, br")
	cleaned.Set("DNT", "1")
	cleaned.Set("Sec-Fetch-Mode", "navigate")

	return cleaned
}

type ProxyServer struct {
	HTTPHandler *ProxyHandler
	SOCKSServer *socks5.Server
	HTTPAddr    string
	SOCKSAddr   string
	Username    *string
	Password    *string
}

type Blocklist struct {
	domains sync.Map
}

func NewBlocklist() *Blocklist {
	return &Blocklist{}
}

func (b *Blocklist) LoadFromURL(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/hosts.txt", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download blocklist: %v", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			b.domains.Store(strings.ToLower(parts[1]), struct{}{})
		}
	}

	return scanner.Err()
}

func (b *Blocklist) IsDomainBlocked(domain string) bool {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}

	domain = strings.ToLower(domain)

	if _, blocked := b.domains.Load(domain); blocked {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		parentDomain := strings.Join(parts[i+1:], ".")
		if _, blocked := b.domains.Load(parentDomain); blocked {
			return true
		}
	}

	return false
}

type ConnectionPool struct {
	pools sync.Map
	size  int32
}

func NewConnectionPool(maxIdleConns int) *ConnectionPool {
	return &ConnectionPool{
		size: int32(maxIdleConns),
	}
}

type connChan struct {
	ch     chan net.Conn
	expiry time.Time
}

func (p *ConnectionPool) Get(key string) (net.Conn, bool) {
	value, ok := p.pools.Load(key)
	if !ok {
		return nil, false
	}

	pool := value.(*connChan)
	if time.Now().After(pool.expiry) {
		p.pools.Delete(key)
		return nil, false
	}

	select {
	case conn := <-pool.ch:
		return conn, true
	default:
		return nil, false
	}
}

func (p *ConnectionPool) Put(key string, conn net.Conn) {
	value, _ := p.pools.LoadOrStore(key, &connChan{
		ch:     make(chan net.Conn, p.size),
		expiry: time.Now().Add(90 * time.Second),
	})

	pool := value.(*connChan)
	select {
	case pool.ch <- conn:
	default:
		conn.Close()
	}
}

type ResponseCache struct {
	cache *lru.Cache[string, *cacheEntry]
}

type cacheEntry struct {
	response *http.Response
	expires  time.Time
}

func NewResponseCache(maxSize int, maxAge time.Duration) *ResponseCache {
	cache, _ := lru.New[string, *cacheEntry](maxSize)
	return &ResponseCache{cache: cache}
}

func (c *ResponseCache) Get(key string) *http.Response {
	entry, ok := c.cache.Get(key)
	if !ok || time.Now().After(entry.expires) {
		return nil
	}
	return entry.response
}

func (c *ResponseCache) Set(key string, resp *http.Response) {
	c.cache.Add(key, &cacheEntry{
		response: resp,
		expires:  time.Now().Add(5 * time.Minute),
	})
}

type ProxyHandler struct {
	Timeout          time.Duration
	Username         *string
	Password         *string
	Cache            *ResponseCache
	Pool             *ConnectionPool
	Blocklist        *Blocklist
	Transport        http.RoundTripper
	headerAnonymizer *HeaderAnonymizer
	sem              *semaphore.Weighted
}

func NewProxyServer(httpAddr, socksAddr string, timeoutSeconds int, username, password *string) (*ProxyServer, error) {
	httpHandler := NewProxyHandler(timeoutSeconds)
	httpHandler.Username = username
	httpHandler.Password = password

	socksConfig := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return httpHandler.getConnection(ctx, addr)
		},
	}

	if username != nil && password != nil {
		socksConfig.Credentials = socks5.StaticCredentials{
			*username: *password,
		}
	}

	socksServer, err := socks5.New(socksConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 server: %v", err)
	}

	return &ProxyServer{
		HTTPHandler: httpHandler,
		SOCKSServer: socksServer,
		HTTPAddr:    httpAddr,
		SOCKSAddr:   socksAddr,
		Username:    username,
		Password:    password,
	}, nil
}

func NewProxyHandler(timeoutSeconds int) *ProxyHandler {
	blocklist := NewBlocklist()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := blocklist.LoadFromURL(ctx); err != nil {
		fmt.Printf("Warning: Failed to load blocklist: %v\n", err)
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		MaxConnsPerHost:       200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
	}
	http2.ConfigureTransport(transport)

	return &ProxyHandler{
		Timeout:          time.Duration(timeoutSeconds) * time.Second,
		Cache:            NewResponseCache(10000, 5*time.Minute),
		Pool:             NewConnectionPool(1000),
		Blocklist:        blocklist,
		Transport:        transport,
		headerAnonymizer: NewHeaderAnonymizer(),
		sem:              semaphore.NewWeighted(5000),
	}
}
func (ps *ProxyServer) Start() error {
	errChan := make(chan error, 2)

	go func() {
		fmt.Printf("Starting HTTP proxy on %s\n", ps.HTTPAddr)
		errChan <- http.ListenAndServe(ps.HTTPAddr, ps.HTTPHandler)
	}()

	go func() {
		fmt.Printf("Starting SOCKS5 proxy on %s\n", ps.SOCKSAddr)
		listener, err := net.Listen("tcp", ps.SOCKSAddr)
		if err != nil {
			errChan <- fmt.Errorf("failed to start SOCKS5 listener: %v", err)
			return
		}
		errChan <- ps.SOCKSServer.Serve(listener)
	}()

	return <-errChan
}
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.sem.TryAcquire(1) {
		http.Error(w, "Too many concurrent connections", http.StatusServiceUnavailable)
		return
	}
	defer p.sem.Release(1)

	if p.Username != nil && p.Password != nil {
		username, password, ok := proxyBasicAuth(r)
		if !ok || username != *p.Username || password != *p.Password {
			w.Header().Set("Proxy-Authenticate", "Basic")
			http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
			return
		}
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	if p.Blocklist.IsDomainBlocked(host) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *ProxyHandler) handleTunneling(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}

	destAddr := net.JoinHostPort(host, port)
	conn, err := p.getConnection(ctx, destAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		conn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		conn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go transferWithBuffer(conn, client_conn)
	go transferWithBuffer(client_conn, conn)
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

func transferWithBuffer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()

	buf := bufferPool.Get().([]byte)
	io.CopyBuffer(dst, src, buf)
	bufferPool.Put(buf)
}
func (p *ProxyHandler) getConnection(ctx context.Context, addr string) (net.Conn, error) {
	if conn, ok := p.Pool.Get(addr); ok {
		return conn, nil
	}

	dialer := &net.Dialer{
		Timeout:   p.Timeout,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	p.Pool.Put(addr, conn)
	return conn, nil
}

func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request) {
	req.Header = p.headerAnonymizer.anonymizeHeaders(req.Header)

	if cachedResp := p.Cache.Get(req.URL.String()); cachedResp != nil {
		copyHeader(w.Header(), cachedResp.Header)
		w.WriteHeader(cachedResp.StatusCode)
		io.Copy(w, cachedResp.Body)
		return
	}

	outreq := req.Clone(req.Context())
	if req.ContentLength == 0 {
		outreq.Body = nil
	}
	if outreq.Body != nil {
		defer outreq.Body.Close()
	}

	removeHopByHopHeaders(outreq.Header)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := p.Transport.RoundTrip(outreq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)

	if isCacheable(req, resp) {
		p.Cache.Set(req.URL.String(), resp)
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

var hopHeaders = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func removeHopByHopHeaders(header http.Header) {
	for h := range header {
		if hopHeaders[h] {
			header.Del(h)
		}
	}
}

func proxyBasicAuth(req *http.Request) (username, password string, ok bool) {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func isCacheable(req *http.Request, resp *http.Response) bool {
	if len(req.Header.Get("Authorization")) > 0 {
		return false
	}

	if req.Method != http.MethodGet {
		return false
	}

	respCC := parseCacheControl(resp.Header.Get("Cache-Control"))
	if respCC.noStore || respCC.noCache || respCC.private {
		return false
	}

	if respCC.public {
		return true
	}

	_, _, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	return err == nil
}

type cacheControl struct {
	noCache bool
	noStore bool
	public  bool
	private bool
	maxAge  int
}

func parseCacheControl(header string) cacheControl {
	cc := cacheControl{}
	parts := strings.Split(header, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "no-cache" {
			cc.noCache = true
		} else if part == "no-store" {
			cc.noStore = true
		} else if part == "public" {
			cc.public = true
		} else if part == "private" {
			cc.private = true
		} else if strings.HasPrefix(part, "max-age=") {
			maxAge := strings.TrimPrefix(part, "max-age=")
			if age, err := time.ParseDuration(maxAge + "s"); err == nil {
				cc.maxAge = int(age.Seconds())
			}
		}
	}

	return cc
}
