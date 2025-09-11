package recursive

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	rand "math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

const (
	maxDepth = 32   // maximum recursion depth
	maxSteps = 1000 // max number of steps to allow in resolving

	// Cookie management constants
	maxSrvCookies = 8192
	srvCookieTTL  = 24 * time.Hour

	// Connection and timeout defaults
	DefaultTimeout = 5 * time.Second
)

// serverCookie represents a DNS server cookie with timestamp
type serverCookie struct {
	value     string
	timestamp time.Time
}

// isExpired checks if the cookie has expired
func (sc *serverCookie) isExpired() bool {
	return time.Since(sc.timestamp) > srvCookieTTL
}

// Recursive implements a recursive DNS resolver with QNAME minimization and caching
type Recursive struct {
	// Configuration (read-only after creation)
	proxy.ContextDialer               // Network dialer for connections
	Cacher                            // Default cache implementation
	*net.Resolver                     // Standard library resolver using our dialer
	Timeout             time.Duration // Individual query timeout
	DefaultLogWriter    io.Writer     // Default debug log writer

	// Rate limiting
	rateLimiter <-chan struct{}

	// Mutable state (protected by mutex)
	mu                sync.RWMutex
	config            *resolverConfig
	networkErrors     *networkErrorManager
	clientCookie      string
	serverCookies     map[netip.Addr]*serverCookie
	lastCookieCleanup time.Time

	// Function override for testing
	dnsResolve func(context.Context, string, uint16) (*dns.Msg, netip.Addr, error)
}

// resolverConfig holds the current resolver configuration
type resolverConfig struct {
	useUDP      bool
	useIPv4     bool
	useIPv6     bool
	rootServers []netip.Addr
}

// Global default cache instance
var DefaultCache = NewCache()

// NewWithOptions creates a new Recursive resolver with specified options
func NewWithOptions(dialer proxy.ContextDialer, cache Cacher, roots4, roots6 []netip.Addr, rateLimiter <-chan struct{}) *Recursive {
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	// Use default roots if none provided
	if roots4 == nil {
		roots4 = Roots4
	}
	if roots6 == nil {
		roots6 = Roots6
	}

	// Prepare root server lists with randomization
	rootServers := prepareRootServers(roots4, roots6)

	r := &Recursive{
		ContextDialer: dialer,
		Cacher:        cache,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     dialer.DialContext,
		},
		Timeout:           DefaultTimeout,
		rateLimiter:       rateLimiter,
		networkErrors:     newNetworkErrorManager(),
		clientCookie:      generateClientCookie(),
		serverCookies:     make(map[netip.Addr]*serverCookie),
		lastCookieCleanup: time.Now(),
		config: &resolverConfig{
			useUDP:      true,
			useIPv4:     len(roots4) > 0,
			useIPv6:     len(roots6) > 0,
			rootServers: rootServers,
		},
	}

	// Set up default resolver function
	r.dnsResolve = r.DnsResolve

	return r
}

// New creates a new Recursive resolver with default cache and calls OrderRoots
func New(dialer proxy.ContextDialer) *Recursive {
	r := NewWithOptions(dialer, DefaultCache, nil, nil, nil)
	r.OrderRoots(context.Background())
	return r
}

// prepareRootServers combines and randomizes IPv4 and IPv6 root servers
func prepareRootServers(roots4, roots6 []netip.Addr) []netip.Addr {
	// Copy and shuffle each list
	var shuffled4, shuffled6 []netip.Addr
	if len(roots4) > 0 {
		shuffled4 = make([]netip.Addr, len(roots4))
		copy(shuffled4, roots4)
		shuffleAddresses(shuffled4)
	}
	if len(roots6) > 0 {
		shuffled6 = make([]netip.Addr, len(roots6))
		copy(shuffled6, roots6)
		shuffleAddresses(shuffled6)
	}

	// Interleave IPv4 and IPv6 addresses for better balance
	rootServers := make([]netip.Addr, 0, len(shuffled4)+len(shuffled6))
	maxLen := max(len(shuffled4), len(shuffled6))

	for i := 0; i < maxLen; i++ {
		if i < len(shuffled4) {
			rootServers = append(rootServers, shuffled4[i])
		}
		if i < len(shuffled6) {
			rootServers = append(rootServers, shuffled6[i])
		}
	}

	return rootServers
}

// shuffleAddresses randomizes the order of addresses
func shuffleAddresses(addresses []netip.Addr) {
	rand.Shuffle(len(addresses), func(i, j int) {
		addresses[i], addresses[j] = addresses[j], addresses[i]
	})
}

// generateClientCookie creates a new random DNS client cookie
func generateClientCookie() string {
	cookieBytes := make([]byte, 8)
	if _, err := crand.Read(cookieBytes); err != nil {
		// Fallback to time-based cookie if random fails
		now := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			cookieBytes[i] = byte(now >> (i * 8))
		}
	}
	return fmt.Sprintf("%x", cookieBytes)
}

// ResetCookies generates a new client cookie and clears server cookies
func (r *Recursive) ResetCookies() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clientCookie = generateClientCookie()
	r.serverCookies = make(map[netip.Addr]*serverCookie)
	r.lastCookieCleanup = time.Now()
}

// OrderRoots sorts root servers by latency and removes unresponsive ones
func (r *Recursive) OrderRoots(ctx context.Context) {
	// Set deadline if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		newCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
		ctx = newCtx
	}

	r.mu.Lock()
	currentRoots := make([]netip.Addr, len(r.config.rootServers))
	copy(currentRoots, r.config.rootServers)
	r.mu.Unlock()

	// Test all root servers concurrently
	rootLatencies := r.testRootServers(ctx, currentRoots)

	// Sort by latency and filter working servers
	sort.Slice(rootLatencies, func(i, j int) bool {
		return rootLatencies[i].latency < rootLatencies[j].latency
	})

	// Update configuration with working servers
	r.updateRootConfiguration(rootLatencies)
}

// testRootServers tests all root servers concurrently and returns their latencies
func (r *Recursive) testRootServers(ctx context.Context, roots []netip.Addr) []*rootLatency {
	var wg sync.WaitGroup
	results := make([]*rootLatency, len(roots))

	for i, addr := range roots {
		results[i] = &rootLatency{address: addr, latency: time.Hour} // Default to high latency
		wg.Add(1)

		go func(idx int, addr netip.Addr) {
			defer wg.Done()
			results[idx].latency = r.measureServerLatency(ctx, addr)
		}(i, addr)
	}

	wg.Wait()
	return results
}

// rootLatency represents a root server with its measured latency
type rootLatency struct {
	address netip.Addr
	latency time.Duration
}

// measureServerLatency measures the connection latency to a server
func (r *Recursive) measureServerLatency(ctx context.Context, addr netip.Addr) time.Duration {
	const numProbes = 3

	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}

	target := netip.AddrPortFrom(addr, dnsPort).String()
	var totalLatency time.Duration

	for i := 0; i < numProbes; i++ {
		start := time.Now()
		conn, err := r.DialContext(ctx, network, target)
		if err != nil {
			return time.Hour // Mark as unreachable
		}
		totalLatency += time.Since(start)
		_ = conn.Close()
	}

	return totalLatency / numProbes
}

// updateRootConfiguration updates the root server configuration
func (r *Recursive) updateRootConfiguration(latencies []*rootLatency) {
	r.mu.Lock()
	defer r.mu.Unlock()

	workingRoots := make([]netip.Addr, 0)
	hasIPv4 := false
	hasIPv6 := false

	for _, rl := range latencies {
		if rl.latency < time.Minute { // Only use responsive servers
			workingRoots = append(workingRoots, rl.address)
			if rl.address.Is4() {
				hasIPv4 = true
			} else if rl.address.Is6() {
				hasIPv6 = true
			}
		}
	}

	if len(workingRoots) > 0 {
		r.config.rootServers = workingRoots
		r.config.useIPv4 = hasIPv4
		r.config.useIPv6 = hasIPv6
	}
}

// GetRoots returns the current IPv4 and IPv6 root servers
func (r *Recursive) GetRoots() (roots4, roots6 []netip.Addr) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, addr := range r.config.rootServers {
		if addr.Is4() {
			roots4 = append(roots4, addr)
		} else if addr.Is6() {
			roots6 = append(roots6, addr)
		}
	}

	return roots4, roots6
}

// ResolveWithOptions performs recursive DNS resolution with specified options
func (r *Recursive) ResolveWithOptions(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	// Clean up expired data periodically
	r.cleanupServerCookies()

	// Normalize query name using miekg/dns utilities
	qname = dns.CanonicalName(qname)

	// Check cache first if available
	if cache != nil {
		if msg := cache.DnsGet(qname, qtype); msg != nil {
			return msg, netip.Addr{}, nil
		}
	}

	// Create query context and execute
	qc := newQueryContext(r, cache, logw)
	msg, serverAddr, err := qc.executeQuery(ctx, qname, qtype)

	// Post-process and cache result
	if msg != nil {
		err = qc.validateAndCacheResult(msg, qname, qtype, cache, err)
	}

	// Log final results if debugging
	if qc.shouldLog() {
		qc.logFinalResult(msg, serverAddr, err)
	}

	return msg, serverAddr, err
}

// Cookie management methods

// getServerCookie retrieves a cached server cookie if valid
func (r *Recursive) getServerCookie(addr netip.Addr) (string, bool) {
	r.cleanupServerCookies()

	r.mu.RLock()
	defer r.mu.RUnlock()

	if cookie, exists := r.serverCookies[addr]; exists && !cookie.isExpired() {
		return cookie.value, true
	}

	return "", false
}

// setServerCookie stores a server cookie
func (r *Recursive) setServerCookie(addr netip.Addr, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.serverCookies[addr] = &serverCookie{
		value:     value,
		timestamp: time.Now(),
	}

	// Trigger cleanup if we have too many cookies
	if len(r.serverCookies) > maxSrvCookies {
		r.cleanupServerCookiesLocked()
	}
}

// cleanupServerCookies removes expired cookies periodically
func (r *Recursive) cleanupServerCookies() {
	r.mu.RLock()
	needsCleanup := time.Since(r.lastCookieCleanup) > time.Hour
	r.mu.RUnlock()

	if needsCleanup {
		r.mu.Lock()
		r.cleanupServerCookiesLocked()
		r.lastCookieCleanup = time.Now()
		r.mu.Unlock()
	}
}

// cleanupServerCookiesLocked removes expired cookies (must hold write lock)
func (r *Recursive) cleanupServerCookiesLocked() {
	now := time.Now()
	expiredAddrs := make([]netip.Addr, 0)

	for addr, cookie := range r.serverCookies {
		if now.Sub(cookie.timestamp) > srvCookieTTL {
			expiredAddrs = append(expiredAddrs, addr)
		}
	}

	for _, addr := range expiredAddrs {
		delete(r.serverCookies, addr)
	}

	// If still too many, remove oldest
	if len(r.serverCookies) > maxSrvCookies {
		r.pruneOldestCookies()
	}
}

// pruneOldestCookies removes the oldest cookies when there are too many
func (r *Recursive) pruneOldestCookies() {
	type cookieEntry struct {
		addr      netip.Addr
		timestamp time.Time
	}

	entries := make([]cookieEntry, 0, len(r.serverCookies))
	for addr, cookie := range r.serverCookies {
		entries = append(entries, cookieEntry{
			addr:      addr,
			timestamp: cookie.timestamp,
		})
	}

	// Sort by timestamp (oldest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].timestamp.Before(entries[j].timestamp)
	})

	// Remove oldest entries
	targetSize := maxSrvCookies / 2
	for i := 0; i < len(entries)-targetSize; i++ {
		delete(r.serverCookies, entries[i].addr)
	}
}

// Network capability methods

// isAddressUsable checks if an address can be used for connections
func (r *Recursive) isAddressUsable(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return (r.config.useIPv4 && addr.Is4()) || (r.config.useIPv6 && addr.Is6())
}

// canUseUDP checks if UDP is currently enabled
func (r *Recursive) canUseUDP() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.config.useUDP
}
