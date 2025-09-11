package recursive

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultMinTTL = 10 * time.Second // minimum cache time
	DefaultMaxTTL = 6 * time.Hour    // maximum cache time
	DefaultNXTTL  = time.Hour        // NXDOMAIN cache time
	MaxQtype      = 260              // maximum supported query type

	// Cache performance constants
	cacheCleanupInterval = 5 * time.Minute
	maxCacheEntries      = 10000
)

var _ Cacher = (*Cache)(nil)
var _ Resolver = (*Cache)(nil)

// Cache provides a thread-safe DNS response cache with TTL management
type Cache struct {
	MinTTL time.Duration // minimum cache duration
	MaxTTL time.Duration // maximum cache duration (except successful NS records)
	NXTTL  time.Duration // NXDOMAIN cache duration

	// Atomic counters for statistics
	totalQueries atomic.Uint64
	cacheHits    atomic.Uint64

	// Per-query-type caches
	qtypeCaches []*qtypeCache
}

// NewCache creates a new cache with default settings
func NewCache() *Cache {
	qtypeCaches := make([]*qtypeCache, MaxQtype+1)
	for i := range qtypeCaches {
		qtypeCaches[i] = newQtypeCache()
	}

	return &Cache{
		MinTTL:      DefaultMinTTL,
		MaxTTL:      DefaultMaxTTL,
		NXTTL:       DefaultNXTTL,
		qtypeCaches: qtypeCaches,
	}
}

// HitRatio returns the cache hit ratio as a percentage (0-100)
func (c *Cache) HitRatio() float64 {
	if c == nil {
		return 0
	}

	totalQueries := c.totalQueries.Load()
	if totalQueries == 0 {
		return 0
	}

	cacheHits := c.cacheHits.Load()
	return float64(cacheHits*100) / float64(totalQueries)
}

// Entries returns the total number of cached entries
func (c *Cache) Entries() int {
	if c == nil {
		return 0
	}

	total := 0
	for _, qtypeCache := range c.qtypeCaches {
		total += qtypeCache.size()
	}
	return total
}

// DnsSet stores a DNS message in the cache with appropriate TTL
func (c *Cache) DnsSet(msg *dns.Msg) {
	if c == nil || msg == nil || msg.Zero || len(msg.Question) != 1 {
		return
	}

	qtype := msg.Question[0].Qtype
	if qtype > MaxQtype {
		return
	}

	// Create a copy to avoid external modifications
	cachedMsg := msg.Copy()
	cachedMsg.Zero = true

	// Calculate appropriate TTL
	ttl := c.calculateTTL(msg, qtype)

	// Store in the appropriate qtype cache
	c.qtypeCaches[qtype].set(msg.Question[0].Name, cachedMsg, ttl)
}

// DnsGet retrieves a cached DNS message
func (c *Cache) DnsGet(qname string, qtype uint16) *dns.Msg {
	if c == nil || qtype > MaxQtype {
		return nil
	}

	c.totalQueries.Add(1)

	if msg := c.qtypeCaches[qtype].get(qname); msg != nil {
		c.cacheHits.Add(1)
		return msg
	}

	return nil
}

// DnsResolve implements the Resolver interface for cache-only resolution
func (c *Cache) DnsResolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	msg := c.DnsGet(qname, qtype)
	return msg, netip.Addr{}, nil
}

// Clear removes all cached entries
func (c *Cache) Clear() {
	if c == nil {
		return
	}

	for _, qtypeCache := range c.qtypeCaches {
		qtypeCache.clear()
	}

	// Reset statistics
	c.totalQueries.Store(0)
	c.cacheHits.Store(0)
}

// Clean removes expired entries from the cache
func (c *Cache) Clean() {
	if c == nil {
		return
	}

	now := time.Now()
	for _, qtypeCache := range c.qtypeCaches {
		qtypeCache.clean(now)
	}
}

// calculateTTL determines the appropriate cache TTL for a DNS message
func (c *Cache) calculateTTL(msg *dns.Msg, qtype uint16) time.Duration {
	if msg.Rcode == dns.RcodeNameError {
		return c.NXTTL
	}

	// Use the minimum TTL from the message
	minTTL := time.Duration(MinTTL(msg)) * time.Second
	if minTTL < c.MinTTL {
		minTTL = c.MinTTL
	}

	// Apply maximum TTL limit (except for successful NS responses)
	if qtype != dns.TypeNS || msg.Rcode != dns.RcodeSuccess {
		if minTTL > c.MaxTTL {
			minTTL = c.MaxTTL
		}
	}

	return minTTL
}

// Statistics returns cache performance metrics
type CacheStats struct {
	Entries      int
	HitRatio     float64
	TotalQueries uint64
	CacheHits    uint64
}

// Stats returns current cache statistics
func (c *Cache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}

	return CacheStats{
		Entries:      c.Entries(),
		HitRatio:     c.HitRatio(),
		TotalQueries: c.totalQueries.Load(),
		CacheHits:    c.cacheHits.Load(),
	}
}
