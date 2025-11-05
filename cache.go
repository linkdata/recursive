package recursive

import (
	"context"
	"errors"
	"io"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const DefaultMinTTL = 10 * time.Second // ten seconds
const DefaultMaxTTL = 6 * time.Hour    // six hours
const DefaultNXTTL = time.Hour         // one hour
const MaxQtype = 260

type Cache struct {
	MinTTL time.Duration // always cache responses for at least this long
	MaxTTL time.Duration // never cache responses for longer than this (excepting successful NS responses)
	NXTTL  time.Duration // cache NXDOMAIN responses for this long
	count  atomic.Uint64
	hits   atomic.Uint64
	cq     []*cacheQtype
}

var _ CachingResolver = &Cache{}

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

func (cache *Cache) DnsSet(msg *dns.Msg) {
	if cache != nil && msg != nil && len(msg.Question) == 1 {
		if qtype := msg.Question[0].Qtype; qtype <= MaxQtype {
			if !msg.Zero {
				msg = msg.Copy()
				msg.Zero = true
			}
			ttl := cache.NXTTL
			if msg.Rcode != dns.RcodeNameError {
				ttl = max(cache.MinTTL, time.Duration(minDNSMsgTTL(msg))*time.Second)
				if qtype != dns.TypeNS || msg.Rcode != dns.RcodeSuccess {
					ttl = min(cache.MaxTTL, ttl)
				}
			}
			cache.cq[qtype].set(msg, ttl)
		}
	}
}

func (cache *Cache) DnsGet(qname string, qtype uint16) (msg *dns.Msg) {
	return cache.Get(qname, qtype, false)
}

func (cache *Cache) Get(qname string, qtype uint16, allowstale bool) (msg *dns.Msg) {
	if cache != nil {
		cache.count.Add(1)
		if qtype <= MaxQtype {
			if msg = cache.cq[qtype].get(qname, allowstale); msg != nil {
				cache.hits.Add(1)
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

const cacheMagic = int64(0xCACE0001)

func (cache *Cache) WriteTo(w io.Writer) (n int64, err error) {
	if cache != nil {
		if err = writeInt64(w, &n, cacheMagic); err == nil {
			for _, cq := range cache.cq {
				written, cqerr := cq.WriteTo(w)
				n += written
				err = errors.Join(err, cqerr)
			}
		}
	}
	return
}

var ErrWrongMagic = errors.New("wrong magic number")

func (cache *Cache) ReadFrom(r io.Reader) (n int64, err error) {
	if cache != nil {
		var gotmagic int64
		if gotmagic, err = readInt64(r, &n); err == nil {
			err = ErrWrongMagic
			if gotmagic == cacheMagic {
				err = nil
				for _, cq := range cache.cq {
					numread, cqerr := cq.ReadFrom(r)
					n += numread
					err = errors.Join(err, cqerr)
				}
			}
		}
	}
	return
}

// Merge inserts all entries from other into cache.
// If an entry exists in both, the one that expires last wins.
func (cache *Cache) Merge(other *Cache) {
	if cache != nil && other != nil && cache != other {
		for i := range other.cq {
			other.cq[i].mu.RLock()
			cache.cq[i].mu.Lock()
			for qname, cv := range other.cq[i].cache {
				if oldcv, ok := cache.cq[i].cache[qname]; !ok || cv.expires.After(oldcv.expires) {
					cache.cq[i].cache[qname] = cv
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
				if err = fn(cv.Msg, cv.expires); err != nil {
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
