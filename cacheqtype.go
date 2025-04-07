package recursive

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheQtype struct {
	mu    sync.RWMutex
	cache map[string]cacheValue
}

func newCacheQtype() *cacheQtype {
	return &cacheQtype{cache: make(map[string]cacheValue)}
}

func (cq *cacheQtype) entries() (n int) {
	cq.mu.RLock()
	n = len(cq.cache)
	cq.mu.RUnlock()
	return
}

func (cq *cacheQtype) set(msg *dns.Msg, ttl int) {
	qname := msg.Question[0].Name
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	cq.mu.Lock()
	cq.cache[qname] = cacheValue{Msg: msg, expires: expires}
	cq.mu.Unlock()
}

func (cq *cacheQtype) get(qname string) *dns.Msg {
	cq.mu.RLock()
	cv := cq.cache[qname]
	cq.mu.RUnlock()
	if cv.Msg != nil {
		if time.Since(cv.expires) < 0 {
			return cv.Msg
		}
		cq.mu.Lock()
		delete(cq.cache, qname)
		cq.mu.Unlock()
	}
	return nil
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
