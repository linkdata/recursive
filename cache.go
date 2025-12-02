package recursive

import (
	"context"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const DefaultMinTTL = 10 * time.Second
const DefaultMaxTTL = 24 * 7 * time.Hour
const DefaultNXTTL = time.Hour
const cacheBucketCountBits = 5
const cacheBucketCount = (1 << cacheBucketCountBits)

type Cache struct {
	MinTTL time.Duration // always cache responses for at least this long
	MaxTTL time.Duration // never cache responses for longer than this (excepting successful NS responses)
	NXTTL  time.Duration // cache NXDOMAIN responses for this long
	count  atomic.Uint64
	hits   atomic.Uint64
	cq     [cacheBucketCount]*cacheBucket
}

var _ CachingResolver = &Cache{}

func NewCache() *Cache {
	cache := &Cache{
		MinTTL: DefaultMinTTL,
		MaxTTL: DefaultMaxTTL,
		NXTTL:  DefaultNXTTL,
	}
	for i := range cache.cq {
		cache.cq[i] = newCacheBucket()
	}
	return cache
}

// HitRatio returns the hit ratio as a percentage.
func (cache *Cache) HitRatio() (n float64) {
	if cache != nil {
		if count := cache.count.Load(); count > 0 {
			n = float64(cache.hits.Load()*100) / float64(count)
		}
	}
	return
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

func newBucketKey(qname string, qtype uint16) (key bucketKey) {
	key = bucketKey{qname: qname, qtype: qtype}
	return
}

func (cache *Cache) bucketFor(key bucketKey) (bucket *cacheBucket) {
	bucket = cache.cq[bucketIndexForKey(key)]
	return
}

// DnsSet add a DNS message to the cache.
//
// Does nothing if the message has the Zero flag set, or does not have exactly one Question.
func (cache *Cache) DnsSet(msg *dns.Msg) {
	if cache != nil && msg != nil && !msg.Zero && len(msg.Question) == 1 {
		question := msg.Question[0]
		key := newBucketKey(question.Name, question.Qtype)
		msg = msg.Copy()
		msg.Zero = true
		ttl := cache.NXTTL
		if msg.Rcode != dns.RcodeNameError {
			ttl = max(cache.MinTTL, time.Duration(minDNSMsgTTL(msg))*time.Second)
			if question.Qtype != dns.TypeNS || msg.Rcode != dns.RcodeSuccess {
				ttl = min(cache.MaxTTL, ttl)
			}
		}
		cache.bucketFor(key).set(key, msg, ttl)
	}
}

// DnsGet returns a caches DNS message if one exists that has not expired.
//
// If an expired message is found, it is removed from the cache and nil is returned.
func (cache *Cache) DnsGet(qname string, qtype uint16) (msg *dns.Msg) {
	msg, _ = cache.Get(qname, qtype, false)
	return
}

// Get allows getting stale DNS entries from the cache if allowstale is true.
func (cache *Cache) Get(qname string, qtype uint16, allowstale bool) (msg *dns.Msg, stale bool) {
	if cache != nil {
		cache.count.Add(1)
		key := newBucketKey(qname, qtype)
		if msg, stale = cache.bucketFor(key).get(key, allowstale); msg != nil {
			cache.hits.Add(1)
		}
	}
	return
}

func (cache *Cache) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	msg = cache.DnsGet(qname, qtype)
	return
}

func (cache *Cache) clearLocked() {
	if cache != nil {
		for _, cq := range cache.cq {
			cq.clearLocked()
		}
	}
}

func (cache *Cache) Clear() {
	if cache != nil {
		for _, cq := range cache.cq {
			cq.clear()
		}
	}
}

// CleanBefore removes entries that expired before t from the cache.
func (cache *Cache) CleanBefore(t time.Time) {
	if cache != nil && !t.IsZero() {
		for _, cq := range cache.cq {
			cq.clean(t)
		}
	}
}

// Clean removes stale entries from the cache.
func (cache *Cache) Clean() {
	cache.CleanBefore(time.Now())
}

// Merge inserts all entries from other into cache.
// If an entry exists in both, the one that expires last wins.
func (cache *Cache) Merge(other *Cache) {
	if cache != nil && other != nil && cache != other {
		for i := range other.cq {
			other.cq[i].mu.RLock()
			cache.cq[i].mu.Lock()
			for key, cv := range other.cq[i].cache {
				if oldcv, ok := cache.cq[i].cache[key]; !ok || cv.expires > oldcv.expires {
					cache.cq[i].cache[key] = cv
				}
			}
			cache.cq[i].mu.Unlock()
			other.cq[i].mu.RUnlock()
		}
	}
}

// Walk calls fn for each entry in the cache. If fn returns an error, it stops and returns that error.
func (cache *Cache) Walk(fn func(msg *dns.Msg, expires time.Time) (err error)) (err error) {
	if cache != nil && fn != nil {
		for _, qc := range cache.cq {
			var cvs []cacheValue
			qc.mu.RLock()
			for _, cv := range qc.cache {
				cvs = append(cvs, cv)
			}
			qc.mu.RUnlock()
			for _, cv := range cvs {
				if err = fn(cv.Msg, cv.expiresAt()); err != nil {
					return
				}
			}
		}
	}
	return
}

func minDNSMsgTTL(msg *dns.Msg) (minTTL int) {
	minTTL = math.MaxInt
	if msg != nil {
		for _, rr := range msg.Answer {
			if rr != nil {
				minTTL = min(minTTL, int(rr.Header().Ttl))
			}
		}
		for _, rr := range msg.Ns {
			if rr != nil {
				minTTL = min(minTTL, int(rr.Header().Ttl))
			}
		}
		for _, rr := range msg.Extra {
			if rr != nil {
				if rr.Header().Rrtype != dns.TypeOPT {
					minTTL = min(minTTL, int(rr.Header().Ttl))
				}
			}
		}
	}
	if minTTL == math.MaxInt {
		minTTL = -1
	}
	return
}
