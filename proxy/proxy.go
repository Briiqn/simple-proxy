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

	"github.com/hashicorp/golang-lru/v2"
	"github.com/pquerna/cachecontrol"
	"golang.org/x/net/http2"
	"golang.org/x/sync/semaphore"
)

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
	Timeout   time.Duration
	Username  *string
	Password  *string
	Cache     *ResponseCache
	Pool      *ConnectionPool
	Blocklist *Blocklist
	Transport http.RoundTripper
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
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		Cache:     NewResponseCache(10000, 5*time.Minute),
		Pool:      NewConnectionPool(1000),
		Blocklist: blocklist,
		Transport: transport,
		sem:       semaphore.NewWeighted(5000),
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
