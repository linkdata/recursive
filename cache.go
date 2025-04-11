package recursive

import (
	"context"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const DefaultMinTTL = 10
const DefaultMaxTTL = 3600
const DefaultNXTTL = 600
const MaxQtype = 260

var _ Cacher = (*Cache)(nil)
var _ Resolver = (*Cache)(nil)

type Cache struct {
	MinTTL int    // always cache responses for at least this long
	MaxTTL int    // never cache responses for longer than this (excepting successful NS responses)
	NXTTL  int    // cache NXDOMAIN responses for this long
	count  uint64 // atomic
	hits   uint64 // atomic
	cq     []*cacheQtype
}

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
	if cache != nil {
		if count := atomic.LoadUint64(&cache.count); count > 0 {
			hits := atomic.LoadUint64(&cache.hits)
			return float64(hits*100) / float64(count)
		}
	}
	return 0
}

// Entries returns the number of entries in the cache.
func (cache *Cache) Entries() (n int) {
	if cache != nil {
		for _, cq := range cache.cq {
			n += cq.entries()
		}
	}
	return
}

func (cache *Cache) DnsSet(msg *dns.Msg) {
	if cache != nil && msg != nil && !msg.Zero && len(msg.Question) == 1 {
		if qtype := msg.Question[0].Qtype; qtype <= MaxQtype {
			msg = msg.Copy()
			msg.Zero = true
			var ttl int
			if msg.Rcode == dns.RcodeNameError {
				ttl = cache.NXTTL
			} else {
				ttl = max(cache.MinTTL, MinTTL(msg))
				if qtype != dns.TypeNS || msg.Rcode != dns.RcodeSuccess {
					ttl = min(cache.MaxTTL, ttl)
				}
			}
			cache.cq[qtype].set(msg, ttl)
		}
	}
}

func (cache *Cache) DnsGet(qname string, qtype uint16) (msg *dns.Msg) {
	if cache != nil {
		atomic.AddUint64(&cache.count, 1)
		if qtype <= MaxQtype {
			if msg = cache.cq[qtype].get(qname); msg != nil {
				atomic.AddUint64(&cache.hits, 1)
			}
		}
	}
	return
}

func (cache *Cache) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	msg = cache.DnsGet(qname, qtype)
	return
}

func (cache *Cache) Clear() {
	if cache != nil {
		for _, cq := range cache.cq {
			cq.clear()
		}
	}
}

func (cache *Cache) Clean() {
	if cache != nil {
		now := time.Now()
		for _, cq := range cache.cq {
			cq.clean(now)
		}
	}
}

// MinTTL returns the lowest resource record TTL in the message, or -1 if there are no records.
func MinTTL(msg *dns.Msg) int {
	minTTL := math.MaxInt
	for _, rr := range msg.Answer {
		minTTL = min(minTTL, int(rr.Header().Ttl))
	}
	for _, rr := range msg.Ns {
		minTTL = min(minTTL, int(rr.Header().Ttl))
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			minTTL = min(minTTL, int(rr.Header().Ttl))
		}
	}
	if minTTL == math.MaxInt {
		minTTL = -1
	}
	return minTTL
}
