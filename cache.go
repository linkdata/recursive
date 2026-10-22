package recursive

import (
	"context"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultMinTTL        = 10
	DefaultMaxTTL        = 7 * 24 * 60 * 60
	DefaultNXTTL         = 60 * 60
	cacheBucketCountBits = 5
	cacheBucketCount     = (1 << cacheBucketCountBits)
)

// Cache stores DNS replies for a [Recursive] resolver.
//
// Use [NewCache] to initialize it; the zero value is not usable.
type Cache struct {
	MinTTL uint32 // always cache responses for at least this long seconds
	MaxTTL uint32 // never cache responses for longer than this seconds (excepting successful NS responses)
	NXTTL  uint32 // cache NXDOMAIN responses for this long seconds
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
	bucket = cache.cq[bucketIndexForQname(key.qname)]
	return
}

// DnsSet adds a DNS message to the cache.
//
// It copies accepted messages before storage. A nil Cache does nothing. Nil
// messages, messages with the Zero flag set, and messages without exactly one
// Question are ignored.
func (cache *Cache) DnsSet(msg *dns.Msg) {
	if cache != nil && msg != nil && !msg.Zero && len(msg.Question) == 1 {
		question := msg.Question[0]
		key := newBucketKey(question.Name, question.Qtype)
		msg = msg.Copy()
		msg.Zero = true
		ttl := cache.NXTTL
		if msg.Rcode != dns.RcodeNameError {
			ttl = max(cache.MinTTL, minDNSMsgTTL(msg))
			if question.Qtype != dns.TypeNS || msg.Rcode != dns.RcodeSuccess {
				ttl = min(cache.MaxTTL, ttl)
			}
		}
		cache.bucketFor(key).set(msg, time.Now().Unix()+int64(ttl))
	}
}

// DnsGet returns an unexpired cached DNS message.
//
// A nil Cache returns nil. Expired entries are removed. Returned messages have
// [dns.Msg.Zero] set and must be treated as immutable. Record TTLs are capped
// at the remaining cache lifetime, except for OPT pseudo-records.
func (cache *Cache) DnsGet(qname string, qtype uint16) (msg *dns.Msg) {
	msg, _ = cache.Get(qname, qtype, nil)
	return
}

func defaultAllowFn(msg *dns.Msg, ttl time.Duration) bool {
	return ttl > 0
}

// Get returns a cached DNS message accepted by allowfn.
//
// The callback receives the stored message and its remaining lifetime. If it
// returns false, that entry is removed. A nil callback rejects stale entries.
// The stale result reports whether a found entry has expired. A nil Cache
// returns nil and false. Returned messages follow the same immutable and TTL
// rules as [Cache.DnsGet].
func (cache *Cache) Get(qname string, qtype uint16, allowfn func(msg *dns.Msg, ttl time.Duration) bool) (msg *dns.Msg, stale bool) {
	var remaining uint32
	msg, stale, remaining = cache.getRaw(qname, qtype, allowfn)
	msg = clampCachedMessage(msg, remaining)
	return
}

func (cache *Cache) getRaw(qname string, qtype uint16, allowfn func(msg *dns.Msg, ttl time.Duration) bool) (msg *dns.Msg, stale bool, remaining uint32) {
	// Cached messages are immutable. Callers clamp before exposing a response.
	if cache != nil {
		if allowfn == nil {
			allowfn = defaultAllowFn
		}
		cache.count.Add(1)
		key := newBucketKey(qname, qtype)
		if msg, stale, remaining = cache.bucketFor(key).get(key, allowfn); msg != nil {
			cache.hits.Add(1)
		}
	}
	return
}

func (cache *Cache) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	msg = cache.DnsGet(qname, qtype)
	return
}

// CleanAllow calls allowfn with 't' as the time to use to determine staleness.
// If allowfn returns false, the cache entry is removed.
func (cache *Cache) CleanAllow(t time.Time, allowfn func(msg *dns.Msg, ttl time.Duration) bool) {
	if cache != nil {
		for _, cq := range cache.cq {
			cq.clean(t, allowfn)
		}
	}
}

// CleanBefore removes entries that expired before t from the cache.
func (cache *Cache) CleanBefore(t time.Time) {
	cache.CleanAllow(t, defaultAllowFn)
}

// Clean removes stale entries from the cache.
func (cache *Cache) Clean() {
	cache.CleanBefore(time.Now())
}

func (cache *Cache) Clear() {
	cache.CleanAllow(time.Time{}, func(msg *dns.Msg, ttl time.Duration) bool { return false })
}

func shouldReplaceMergedEntry(newcv cacheValue, oldcv cacheValue) (replace bool) {
	replace, decided := shouldReplaceForAuthoritative(newcv.Msg, oldcv.Msg)
	if !decided {
		replace = newcv.expires > oldcv.expires
	}
	return
}

// Merge inserts all entries from other into cache.
// If an entry exists in both, authoritative answers take precedence.
// Otherwise, the one that expires last wins.
func (cache *Cache) Merge(other *Cache) {
	if cache != nil && other != nil && cache != other {
		type mergeEntry struct {
			key bucketKey
			cv  cacheValue
		}
		for i := range other.cq {
			var entries []mergeEntry
			other.cq[i].mu.RLock()
			for key, cv := range other.cq[i].cache {
				entries = append(entries, mergeEntry{key: key, cv: cv})
			}
			other.cq[i].mu.RUnlock()
			if len(entries) > 0 {
				cache.cq[i].mu.Lock()
				for _, entry := range entries {
					if oldcv, ok := cache.cq[i].cache[entry.key]; !ok || shouldReplaceMergedEntry(entry.cv, oldcv) {
						cache.cq[i].cache[entry.key] = entry.cv
					}
				}
				cache.cq[i].mu.Unlock()
			}
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

func minDNSMsgTTL(msg *dns.Msg) (minTTL uint32) {
	minTTL = math.MaxUint32
	if msg != nil {
		for _, rr := range msg.Answer {
			if rr != nil {
				minTTL = min(minTTL, rr.Header().Ttl)
			}
		}
		for _, rr := range msg.Ns {
			if rr != nil {
				minTTL = min(minTTL, rr.Header().Ttl)
			}
		}
		for _, rr := range msg.Extra {
			if rr != nil {
				if rr.Header().Rrtype != dns.TypeOPT {
					minTTL = min(minTTL, rr.Header().Ttl)
				}
			}
		}
	}
	if minTTL == math.MaxUint32 {
		minTTL = 0
	}
	return
}

func hasDNSMsgTTLAbove(msg *dns.Msg, ttl uint32) (above bool) {
	if msg != nil {
		for _, records := range [3][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
			for _, rr := range records {
				if rr != nil {
					hdr := rr.Header()
					if hdr.Rrtype != dns.TypeOPT && hdr.Ttl > ttl {
						above = true
						return
					}
				}
			}
		}
	}
	return
}

func clampCachedMessage(msg *dns.Msg, ttl uint32) (out *dns.Msg) {
	out = msg
	if hasDNSMsgTTLAbove(msg, ttl) {
		out = msg.Copy()
		clampMessageTTL(out, ttl)
	}
	return
}

func clampMessageTTL(msg *dns.Msg, ttlSeconds uint32) {
	for _, rr := range msg.Answer {
		clampRRHeaderTTL(rr, ttlSeconds)
	}
	for _, rr := range msg.Ns {
		clampRRHeaderTTL(rr, ttlSeconds)
	}
	for _, rr := range msg.Extra {
		clampRRHeaderTTL(rr, ttlSeconds)
	}
}

func clampRRHeaderTTL(rr dns.RR, ttlSeconds uint32) {
	if hdr := rr.Header(); hdr.Rrtype != dns.TypeOPT {
		if hdr.Ttl > ttlSeconds {
			hdr.Ttl = ttlSeconds
		}
	}
}
