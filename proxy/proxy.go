package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/cachecontrol"
	"golang.org/x/net/http2"
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

func (b *Blocklist) LoadFromURL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download blocklist: %v", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	b.mu.Lock()
	defer b.mu.Unlock()

	b.domains = make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			domain := parts[1]
			b.domains[domain] = struct{}{}
		}
	}

	return scanner.Err()
}

func (b *Blocklist) IsDomainBlocked(domain string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}

	_, blocked := b.domains[domain]
	return blocked
}

type TunnelCache struct {
	connections map[string]*net.Conn
	mu          sync.RWMutex
	expiry      map[string]time.Time
}

func NewTunnelCache() *TunnelCache {
	cache := &TunnelCache{
		connections: make(map[string]*net.Conn),
		expiry:      make(map[string]time.Time),
	}
	go cache.cleanupRoutine()
	return cache
}

func (c *TunnelCache) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		c.cleanup()
	}
}

func (c *TunnelCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, exp := range c.expiry {
		if now.After(exp) {
			if conn, exists := c.connections[key]; exists {
				(*conn).Close()
				delete(c.connections, key)
				delete(c.expiry, key)
			}
		}
	}
}

func (c *TunnelCache) Set(key string, conn *net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connections[key] = conn
	c.expiry[key] = time.Now().Add(5 * time.Minute)
}

func (c *TunnelCache) Get(key string) (*net.Conn, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	conn, exists := c.connections[key]
	if exists {
		c.expiry[key] = time.Now().Add(5 * time.Minute)
		return conn, true
	}
	return nil, false
}

type Cache struct {
	items map[string]*http.Response
	mu    sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{
		items: make(map[string]*http.Response),
	}
}

func (c *Cache) Get(req *http.Request) *http.Response {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.items[req.URL.String()]
}

func (c *Cache) Set(req *http.Request, resp *http.Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[req.URL.String()] = resp
}

type DNSCache struct {
	items map[string]string
	mu    sync.RWMutex
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		items: make(map[string]string),
	}
}

func (c *DNSCache) Get(domain string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.items[domain]
}

func (c *DNSCache) Set(domain, ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[domain] = ip
}

type ProxyHandler struct {
	Timeout     time.Duration
	Username    *string
	Password    *string
	Cache       *Cache
	DNSCache    *DNSCache
	TunnelCache *TunnelCache
	Blocklist   *Blocklist
}

func NewProxyHandler(timeoutSeconds int) *ProxyHandler {
	blocklist := NewBlocklist()
	// Download and load the blocklist
	err := blocklist.LoadFromURL("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/hosts.txt")
	if err != nil {
		fmt.Printf("Warning: Failed to load blocklist: %v\n", err)
	} else {
		fmt.Printf("Loaded Blocklist Sucessfully")

	}

	return &ProxyHandler{
		Timeout:     time.Duration(timeoutSeconds) * time.Second,
		Cache:       NewCache(),
		DNSCache:    NewDNSCache(),
		TunnelCache: NewTunnelCache(),
		Blocklist:   blocklist,
	}
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.Username != nil && p.Password != nil {
		username, password, ok := proxyBasicAuth(r)
		if !ok || username != *p.Username || password != *p.Password {
			w.Header().Set("Proxy-Authenticate", "Basic")
			http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
			return
		}
	}

	// Check if domain is blocked
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	if p.Blocklist.IsDomainBlocked(host) {
		http.Error(w, "Access to this domain is blocked", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *ProxyHandler) handleTunneling(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}

	cacheKey := fmt.Sprintf("%s:%s", host, port)

	if cachedConn, exists := p.TunnelCache.Get(cacheKey); exists {
		if err := p.reuseConnection(w, r, cachedConn); err == nil {
			return
		}
	}

	ip, err := p.resolveDomainDoH(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	dest_conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), p.Timeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	p.TunnelCache.Set(cacheKey, &dest_conn)

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go p.transfer(dest_conn, client_conn)
	go p.transfer(client_conn, dest_conn)
}

func (p *ProxyHandler) reuseConnection(w http.ResponseWriter, r *http.Request, cachedConn *net.Conn) error {
	(*cachedConn).SetReadDeadline(time.Now())
	_, err := (*cachedConn).Read(make([]byte, 0))
	(*cachedConn).SetReadDeadline(time.Time{})

	if err != nil && !strings.Contains(err.Error(), "timeout") {
		return fmt.Errorf("cached connection is dead")
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("hijacking not supported")
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack connection: %v", err)
	}

	go p.transfer(*cachedConn, client_conn)
	go p.transfer(client_conn, *cachedConn)

	return nil
}

func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if cachedResp := p.Cache.Get(req); cachedResp != nil {
		copyHeader(w.Header(), cachedResp.Header)
		w.WriteHeader(cachedResp.StatusCode)
		io.Copy(w, cachedResp.Body)
		return
	}

	ip, err := p.resolveDomainDoH(req.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	req.URL.Host = ip

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

	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	if isCacheable(req, resp) {
		p.Cache.Set(req, resp)
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *ProxyHandler) resolveDomainDoH(domain string) (string, error) {
	if cachedIP := p.DNSCache.Get(domain); cachedIP != "" {
		return cachedIP, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	packed, err := m.Pack()
	if err != nil {
		return "", fmt.Errorf("failed to pack DNS message")
	}

	b64 := base64.RawURLEncoding.EncodeToString(packed)

	req, err := http.NewRequest(http.MethodGet, "https://cloudflare-dns.com/dns-query", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request")
	}

	req.Header.Set("accept", "application/dns-message")
	q := req.URL.Query()
	q.Add("dns", b64)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make DoH request %s", err.Error())
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body")
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return "", fmt.Errorf("failed to unpack DNS response")
	}

	if len(r.Answer) == 0 {
		return "", fmt.Errorf("no DNS answer for domain")
	}

	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			p.DNSCache.Set(domain, a.A.String())
			return a.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record found for domain")
}

func (p *ProxyHandler) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
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
