package recursive

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultMinTTL = 10 * time.Second // ten seconds
	DefaultMaxTTL = 6 * time.Hour    // six hours
	DefaultNXTTL  = time.Hour        // one hour
	MaxQtype      = 260
)

var _ Cacher = (*Cache)(nil)
var _ Resolver = (*Cache)(nil)

// Cache provides DNS response caching with configurable TTL limits
type Cache struct {
	MinTTL time.Duration // always cache responses for at least this long
	MaxTTL time.Duration // never cache responses for longer than this (excepting successful NS responses)
	NXTTL  time.Duration // cache NXDOMAIN responses for this long

	count atomic.Uint64
	hits  atomic.Uint64
	cq    []*cacheQtype
}

// NewCache creates a new cache with default TTL settings
func NewCache() *Cache {
	cq := make([]*cacheQtype, MaxQtype+1)
	for i := range cq {
		cq[i] = newCacheQtype()
	}
	return &Cache{
		MinTTL: DefaultMinTTL,
		MaxTTL: DefaultMaxTTL,
		NXTTL:  DefaultNXTTL,
		cq:     cq,
	}
}

// HitRatio returns the hit ratio as a percentage.
func (cache *Cache) HitRatio() float64 {
	if cache == nil {
		return 0
	}

	count := cache.count.Load()
	if count == 0 {
		return 0
	}

	return float64(cache.hits.Load()*100) / float64(count)
}

// Entries returns the number of entries in the cache.
func (cache *Cache) Entries() int {
	if cache == nil {
		return 0
	}

	n := 0
	for _, cq := range cache.cq {
		n += cq.entries()
	}
	return n
}

// DnsSet stores a DNS message in the cache
func (cache *Cache) DnsSet(msg *dns.Msg) {
	if cache == nil || msg == nil || msg.Zero || len(msg.Question) != 1 {
		return
	}

	qtype := msg.Question[0].Qtype
	if qtype > MaxQtype {
		return
	}

	msg = msg.Copy()
	msg.Zero = true

	ttl := cache.calculateTTL(msg, qtype)
	cache.cq[qtype].set(msg, ttl)
}

// DnsGet retrieves a DNS message from the cache
func (cache *Cache) DnsGet(qname string, qtype uint16) *dns.Msg {
	if cache == nil {
		return nil
	}

	cache.count.Add(1)

	if qtype > MaxQtype {
		return nil
	}

	msg := cache.cq[qtype].get(qname)
	if msg != nil {
		cache.hits.Add(1)
	}

	return msg
}

// DnsResolve implements the Resolver interface for cache-only resolution
func (cache *Cache) DnsResolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	msg := cache.DnsGet(qname, qtype)
	return msg, netip.Addr{}, nil
}

// Clear removes all entries from the cache
func (cache *Cache) Clear() {
	if cache == nil {
		return
	}

	for _, cq := range cache.cq {
		cq.clear()
	}
}

// Clean removes expired entries from the cache
func (cache *Cache) Clean() {
	if cache == nil {
		return
	}

	now := time.Now()
	for _, cq := range cache.cq {
		cq.clean(now)
	}
}

func (cache *Cache) calculateTTL(msg *dns.Msg, qtype uint16) time.Duration {
	if msg.Rcode == dns.RcodeNameError {
		return cache.NXTTL
	}

	ttl := max(cache.MinTTL, time.Duration(MinTTL(msg))*time.Second)

	// Don't limit TTL for successful NS responses
	if qtype != dns.TypeNS || msg.Rcode != dns.RcodeSuccess {
		ttl = min(cache.MaxTTL, ttl)
	}

	return ttl
}

// cacheQtype manages cache entries for a specific query type
type cacheQtype struct {
	mu    sync.RWMutex
	cache map[string]cacheValue
}

func newCacheQtype() *cacheQtype {
	return &cacheQtype{
		cache: make(map[string]cacheValue),
	}
}

func (cq *cacheQtype) entries() int {
	cq.mu.RLock()
	n := len(cq.cache)
	cq.mu.RUnlock()
	return n
}

func (cq *cacheQtype) set(msg *dns.Msg, ttl time.Duration) {
	qname := msg.Question[0].Name
	expires := time.Now().Add(ttl)

	cq.mu.Lock()
	cq.cache[qname] = cacheValue{Msg: msg, expires: expires}
	cq.mu.Unlock()
}

func (cq *cacheQtype) get(qname string) *dns.Msg {
	cq.mu.RLock()
	cv := cq.cache[qname]
	cq.mu.RUnlock()

	if cv.Msg == nil {
		return nil
	}

	if time.Since(cv.expires) >= 0 {
		// Entry has expired, remove it
		cq.mu.Lock()
		delete(cq.cache, qname)
		cq.mu.Unlock()
		return nil
	}

	return cv.Msg
}

func (cq *cacheQtype) clear() {
	cq.clean(time.Time{})
}

func (cq *cacheQtype) clean(now time.Time) {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	for qname, cv := range cq.cache {
		if now.IsZero() || now.After(cv.expires) {
			delete(cq.cache, qname)
		}
	}
}

// cacheValue stores a cached DNS message with its expiration time
type cacheValue struct {
	*dns.Msg
	expires time.Time
}
