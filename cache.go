package recursive

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Cache struct {
	count uint64 // atomic
	hits  uint64 // atomic
	mu    sync.RWMutex
	cache map[cacheKey]cacheValue
}

func NewCache() *Cache {
	return &Cache{
		cache: make(map[cacheKey]cacheValue),
	}
}

// HitRatio returns the hit ratio as a percentage.
func (cache *Cache) HitRatio() float64 {
	if cache != nil {
		if count := atomic.LoadUint64(&cache.count); count > 0 {
			hits := atomic.LoadUint64(&cache.hits)
			return float64(hits*100) / float64(count)
		}
	}
	return 0
}

// Size returns the number of entries in the cache.
func (cache *Cache) Size() (n int) {
	if cache != nil {
		cache.mu.RLock()
		n = len(cache.cache)
		cache.mu.RUnlock()
	}
	return
}

func (cache *Cache) Set(nsaddr netip.Addr, qname string, qtype uint16, msg *dns.Msg) {
	if cache != nil && msg != nil {
		ttl := min(MinTTL(msg), maxCacheTTL)
		if ttl < 0 {
			// empty response, cache it for a while
			ttl = maxCacheTTL / 10
		}
		cv := cacheValue{
			Msg:     msg,
			expires: time.Now().Add(time.Duration(ttl) * time.Second),
		}
		cache.mu.Lock()
		cache.cache[cacheKey{
			nsaddr: nsaddr,
			qname:  qname,
			qtype:  qtype,
		}] = cv
		cache.mu.Unlock()
	}
}

func (cache *Cache) Get(nsaddr netip.Addr, qname string, qtype uint16) *dns.Msg {
	if cache != nil {
		ck := cacheKey{
			nsaddr: nsaddr,
			qname:  qname,
			qtype:  qtype,
		}
		cache.mu.RLock()
		cv, ok := cache.cache[ck]
		cache.mu.RUnlock()
		atomic.AddUint64(&cache.count, 1)
		if ok {
			if time.Since(cv.expires) < 0 {
				atomic.AddUint64(&cache.hits, 1)
				return cv.Msg
			}
			cache.mu.Lock()
			delete(cache.cache, ck)
			cache.mu.Unlock()
		}
	}
	return nil
}

func (cache *Cache) Clean(now time.Time) {
	if cache != nil {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if now.IsZero() {
			clear(cache.cache)
			return
		}
		for ck, cv := range cache.cache {
			if now.After(cv.expires) {
				delete(cache.cache, ck)
			}
		}
	}
}
