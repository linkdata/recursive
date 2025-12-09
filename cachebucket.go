package recursive

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type bucketKey struct {
	qname string
	qtype uint16
}

type cacheBucket struct {
	mu    sync.RWMutex
	cache map[bucketKey]cacheValue
}

func newCacheBucket() *cacheBucket {
	return &cacheBucket{cache: make(map[bucketKey]cacheValue)}
}

var bucketSeed = maphash.MakeSeed()

func bucketIndexForQname(qname string) (idx int) {
	idx = int(maphash.String(bucketSeed, qname) & (cacheBucketCount - 1)) // #nosec G115
	return
}

func (cq *cacheBucket) entries() (n int) {
	cq.mu.RLock()
	n = len(cq.cache)
	cq.mu.RUnlock()
	return
}

func questionBucketKey(q dns.Question) bucketKey {
	return newBucketKey(q.Name, q.Qtype)
}

func (cq *cacheBucket) setLocked(msg *dns.Msg, expires int64) {
	cq.cache[questionBucketKey(msg.Question[0])] = cacheValue{Msg: msg, expires: expires}
}

func (cq *cacheBucket) set(msg *dns.Msg, expires int64) {
	cq.mu.Lock()
	cq.setLocked(msg, expires)
	cq.mu.Unlock()
}

func (cq *cacheBucket) get(key bucketKey, allowfn func(msg *dns.Msg, stale bool) bool) (msg *dns.Msg, stale bool) {
	cq.mu.RLock()
	cv := cq.cache[key]
	cq.mu.RUnlock()
	if cv.Msg != nil {
		stale = time.Since(cv.expiresAt()) > 0
		if allowfn(cv.Msg, stale) {
			msg = cv.Msg
		} else {
			cq.mu.Lock()
			delete(cq.cache, key)
			cq.mu.Unlock()
		}
	}
	return
}

func (cq *cacheBucket) clear() {
	cq.clean(time.Time{})
}

func (cq *cacheBucket) cleanLocked(t time.Time) {
	for key, cv := range cq.cache {
		if t.IsZero() || cv.expiresAt().Before(t) {
			delete(cq.cache, key)
		}
	}
}

func (cq *cacheBucket) clean(t time.Time) {
	cq.mu.Lock()
	defer cq.mu.Unlock()
	cq.cleanLocked(t)
}
