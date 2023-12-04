package recursive

import (
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheQtype struct {
	mu       sync.RWMutex
	havewild bool // true if netip.Addr{} exists in keys
	cache    map[cacheKey]cacheValue
}

func (cq *cacheQtype) entries() (n int) {
	cq.mu.RLock()
	n = len(cq.cache)
	cq.mu.RUnlock()
	return
}

func (cq *cacheQtype) set(nsaddr netip.Addr, msg *dns.Msg, ttl int) {
	ck := cacheKey{
		nsaddr: nsaddr,
		qname:  msg.Question[0].Name,
	}
	cv := cacheValue{
		Msg:     msg,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	cq.mu.Lock()
	defer cq.mu.Unlock()
	cq.havewild = cq.havewild || !ck.nsaddr.IsValid()
	cq.cache[ck] = cv
}

func (cq *cacheQtype) get(nsaddr netip.Addr, qname string) (netip.Addr, *dns.Msg) {
	ck := cacheKey{
		nsaddr: nsaddr,
		qname:  qname,
	}
	cq.mu.RLock()
	cv, ok := cq.cache[ck]
	if !ok && cq.havewild {
		ck.nsaddr = netip.Addr{}
		cv, ok = cq.cache[ck]
	}
	cq.mu.RUnlock()
	if ok {
		if time.Since(cv.expires) < 0 {
			return ck.nsaddr, cv.Msg
		}
		cq.mu.Lock()
		if cv, ok := cq.cache[ck]; ok {
			cq.deleteLocked(ck, cv)
		}
		cq.mu.Unlock()
	}
	return netip.Addr{}, nil
}

func (cq *cacheQtype) clear() {
	cq.mu.Lock()
	cq.havewild = false
	clear(cq.cache)
	cq.mu.Unlock()
}

func (cq *cacheQtype) clean(now time.Time) {
	cq.mu.Lock()
	defer cq.mu.Unlock()
	havewild := false
	for ck, cv := range cq.cache {
		if now.After(cv.expires) {
			cq.deleteLocked(ck, cv)
		} else {
			havewild = havewild || !ck.nsaddr.IsValid()
		}
	}
	cq.havewild = havewild
}

func (cq *cacheQtype) deleteLocked(ck cacheKey, cv cacheValue) {
	clear(cv.Msg.Question)
	clear(cv.Msg.Answer)
	clear(cv.Msg.Ns)
	clear(cv.Msg.Extra)
	delete(cq.cache, ck)
}
