package recursive

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheBucket struct {
	mu    sync.RWMutex
	cache map[string]cacheValue
}

func newCacheBucket() *cacheBucket {
	return &cacheBucket{cache: make(map[string]cacheValue)}
}

func (cq *cacheBucket) entries() (n int) {
	cq.mu.RLock()
	n = len(cq.cache)
	cq.mu.RUnlock()
	return
}

func (cq *cacheBucket) setLocked(msg *dns.Msg, expires int64) {
	qname := msg.Question[0].Name
	cq.cache[qname] = cacheValue{Msg: msg, expires: expires}
}

func (cq *cacheBucket) set(msg *dns.Msg, ttl time.Duration) {
	cq.mu.Lock()
	cq.setLocked(msg, time.Now().Add(ttl).Unix())
	cq.mu.Unlock()
}

func (cq *cacheBucket) get(qname string, allowstale bool) (msg *dns.Msg, stale bool) {
	cq.mu.RLock()
	cv := cq.cache[qname]
	cq.mu.RUnlock()
	if cv.Msg != nil {
		expires := cv.expiresAt()
		stale = time.Since(expires) > 0
		if !stale || allowstale {
			msg = cv.Msg
		} else {
			cq.mu.Lock()
			delete(cq.cache, qname)
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
	for qname, cv := range cq.cache {
		if t.IsZero() || cv.expiresAt().Before(t) {
			delete(cq.cache, qname)
		}
	}
}

func (cq *cacheBucket) clean(t time.Time) {
	cq.mu.Lock()
	defer cq.mu.Unlock()
	cq.cleanLocked(t)
}
