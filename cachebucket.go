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

func bucketIndexForKey(key bucketKey) (idx int) {
	idx = int(maphash.String(bucketSeed, key.qname) & (cacheBucketCount - 1))
	return
}

func (cq *cacheBucket) entries() (n int) {
	cq.mu.RLock()
	n = len(cq.cache)
	cq.mu.RUnlock()
	return
}

func (cq *cacheBucket) setLocked(key bucketKey, msg *dns.Msg, expires int64) {
	cq.cache[key] = cacheValue{Msg: msg, expires: expires}
}

func (cq *cacheBucket) set(key bucketKey, msg *dns.Msg, ttl time.Duration) {
	cq.mu.Lock()
	cq.setLocked(key, msg, time.Now().Add(ttl).Unix())
	cq.mu.Unlock()
}

func (cq *cacheBucket) get(key bucketKey, allowstale bool) (msg *dns.Msg, stale bool) {
	cq.mu.RLock()
	cv := cq.cache[key]
	cq.mu.RUnlock()
	if cv.Msg != nil {
		expires := cv.expiresAt()
		stale = time.Since(expires) > 0
		if !stale || allowstale {
			msg = cv.Msg
		} else {
			cq.mu.Lock()
			delete(cq.cache, key)
			cq.mu.Unlock()
		}
	}
	return
}

func (cq *cacheBucket) clearLocked() {
	cq.cleanLocked(time.Time{})
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
