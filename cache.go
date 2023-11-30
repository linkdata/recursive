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
	wilds int
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

func (cache *Cache) Set(nsaddr netip.Addr, msg *dns.Msg) {
	if cache != nil && msg != nil && len(msg.Question) == 1 {
		ttl := min(MinTTL(msg), maxCacheTTL)
		if ttl < 0 {
			// empty response, cache it for a while
			ttl = maxCacheTTL / 10
		}
		ck := cacheKey{
			nsaddr: nsaddr,
			qname:  msg.Question[0].Name,
			qtype:  msg.Question[0].Qtype,
		}
		cv := cacheValue{
			Msg:     msg,
			expires: time.Now().Add(time.Duration(ttl) * time.Second),
		}
		cache.mu.Lock()
		if !nsaddr.IsValid() {
			if _, ok := cache.cache[ck]; !ok {
				cache.wilds++
			}
		}
		cache.cache[ck] = cv
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
		if !ok && !nsaddr.IsValid() {
			for k, v := range cache.cache {
				if k.qtype == qtype && k.qname == qname {
					if v.expires.After(cv.expires) {
						ck = k
						cv = v
						ok = true
					}
				}
			}
		}
		if !ok && cache.wilds > 0 {
			ck.nsaddr = netip.Addr{}
			cv, ok = cache.cache[ck]
		}
		cache.mu.RUnlock()
		atomic.AddUint64(&cache.count, 1)
		if ok {
			if time.Since(cv.expires) < 0 {
				atomic.AddUint64(&cache.hits, 1)
				return cv.Msg
			}
			cache.mu.Lock()
			cache.deleteLocked(ck)
			cache.mu.Unlock()
		}
	}
	return nil
}

func (cache *Cache) deleteLocked(ck cacheKey) {
	if !ck.nsaddr.IsValid() {
		if _, ok := cache.cache[ck]; ok {
			cache.wilds--
		}
	}
	delete(cache.cache, ck)
}

func (cache *Cache) Clear() {
	cache.mu.Lock()
	clear(cache.cache)
	cache.mu.Unlock()
}

func (cache *Cache) Clean() {
	if cache != nil {
		now := time.Now()
		for ck, cv := range cache.cache {
			if now.After(cv.expires) {
				cache.deleteLocked(ck)
			}
		}
	}
}
