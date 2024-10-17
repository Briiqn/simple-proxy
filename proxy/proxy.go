package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/cachecontrol"
	"golang.org/x/net/http2"
	"golang.org/x/sync/semaphore"
)

type Blocklist struct {
	domains map[string]struct{}
	mu      sync.RWMutex
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		domains: make(map[string]struct{}),
	}
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

	newDomains := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			newDomains[parts[1]] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist: %v", err)
	}

	b.mu.Lock()
	b.domains = newDomains
	b.mu.Unlock()

	return nil
}

func (b *Blocklist) IsDomainBlocked(domain string) bool {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}

	b.mu.RLock()
	_, blocked := b.domains[domain]
	b.mu.RUnlock()
	return blocked
}

type ConnectionPool struct {
	pool    map[string]chan net.Conn
	mu      sync.RWMutex
	maxIdle int
}

func NewConnectionPool(maxIdleConns int) *ConnectionPool {
	return &ConnectionPool{
		pool:    make(map[string]chan net.Conn),
		maxIdle: maxIdleConns,
	}
}

func (p *ConnectionPool) Get(key string) (net.Conn, bool) {
	p.mu.RLock()
	ch, exists := p.pool[key]
	p.mu.RUnlock()

	if !exists {
		return nil, false
	}

	select {
	case conn := <-ch:
		return conn, true
	default:
		return nil, false
	}
}

func (p *ConnectionPool) Put(key string, conn net.Conn) {
	p.mu.Lock()
	if _, exists := p.pool[key]; !exists {
		p.pool[key] = make(chan net.Conn, p.maxIdle)
	}
	p.mu.Unlock()

	select {
	case p.pool[key] <- conn:
	default:
		conn.Close()
	}
}

type ResponseCache struct {
	cache   map[string]*cacheEntry
	mu      sync.RWMutex
	maxAge  time.Duration
	maxSize int
	sem     *semaphore.Weighted
}

type cacheEntry struct {
	response *http.Response
	expires  time.Time
}

func NewResponseCache(maxSize int, maxAge time.Duration) *ResponseCache {
	cache := &ResponseCache{
		cache:   make(map[string]*cacheEntry),
		maxAge:  maxAge,
		maxSize: maxSize,
		sem:     semaphore.NewWeighted(int64(maxSize)),
	}
	go cache.periodicCleanup(context.Background())
	return cache
}

func (c *ResponseCache) periodicCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *ResponseCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expires) {
			delete(c.cache, key)
			c.sem.Release(1)
		}
	}
}

func (c *ResponseCache) Get(key string) *http.Response {
	c.mu.RLock()
	entry, exists := c.cache[key]
	c.mu.RUnlock()

	if !exists || time.Now().After(entry.expires) {
		return nil
	}
	return entry.response
}

func (c *ResponseCache) Set(key string, resp *http.Response) {
	if !c.sem.TryAcquire(1) {
		return
	}

	c.mu.Lock()
	c.cache[key] = &cacheEntry{
		response: resp,
		expires:  time.Now().Add(c.maxAge),
	}
	c.mu.Unlock()
}

type ProxyHandler struct {
	Timeout   time.Duration
	Username  *string
	Password  *string
	Cache     *ResponseCache
	Pool      *ConnectionPool
	Blocklist *Blocklist
	Transport *http.Transport
	sem       *semaphore.Weighted
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
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	http2.ConfigureTransport(transport)

	return &ProxyHandler{
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		Cache:     NewResponseCache(1000, 5*time.Minute),
		Pool:      NewConnectionPool(100),
		Blocklist: blocklist,
		Transport: transport,
		sem:       semaphore.NewWeighted(1000),
	}
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

	go p.transfer(conn, client_conn)
	go p.transfer(client_conn, conn)
}

func (p *ProxyHandler) getConnection(ctx context.Context, addr string) (net.Conn, error) {
	if conn, ok := p.Pool.Get(addr); ok {
		return conn, nil
	}

	dialer := &net.Dialer{Timeout: p.Timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if cachedResp := p.Cache.Get(req.URL.String()); cachedResp != nil {
		copyHeader(w.Header(), cachedResp.Header)
		w.WriteHeader(cachedResp.StatusCode)
		io.Copy(w, cachedResp.Body)
		return
	}

	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	if isCacheable(req, resp) {
		p.Cache.Set(req.URL.String(), resp)
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *ProxyHandler) transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
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
	_, _, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	return err == nil
}
