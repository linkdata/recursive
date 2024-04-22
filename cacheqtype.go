package recursive

import (
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheQtype struct {
	mu    sync.RWMutex
	cache map[string][]cacheValue
}

func newCacheQtype() *cacheQtype {
	return &cacheQtype{cache: make(map[string][]cacheValue)}
}

func (cq *cacheQtype) entries() (n int) {
	cq.mu.RLock()
	for _, cv := range cq.cache {
		n += len(cv)
	}
	cq.mu.RUnlock()
	return
}

func (cq *cacheQtype) set(nsaddr netip.Addr, msg *dns.Msg, ttl int) {
	qname := msg.Question[0].Name
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	cq.mu.Lock()
	defer cq.mu.Unlock()
	cvl := cq.cache[qname]
	for i := range cvl {
		if cvl[i].nsaddr == nsaddr {
			cvl[i].Msg = msg
			cvl[i].expires = expires
			return
		}
	}
	cq.cache[qname] = append(cvl, cacheValue{
		Msg:     msg,
		nsaddr:  nsaddr,
		expires: expires,
	})
}

func find(cvl []cacheValue, addr netip.Addr) (idx int) {
	wild := !addr.IsValid()
	idx = -1
	for i := range cvl {
		if cvl[i].nsaddr == addr {
			idx = i
			break
		}
		if wild {
			wild = false
			idx = i
		}
	}
	return
}

func (cq *cacheQtype) getExisting(addr netip.Addr, qname string) (cv cacheValue) {
	cq.mu.RLock()
	defer cq.mu.RUnlock()
	cvl := cq.cache[qname]
	if idx := find(cvl, addr); idx >= 0 {
		cv = cvl[idx]
	}
	return
}

func (cq *cacheQtype) get(addr netip.Addr, qname string) (netip.Addr, *dns.Msg) {
	if cv := cq.getExisting(addr, qname); cv.Msg != nil {
		if time.Since(cv.expires) < 0 {
			return cv.nsaddr, cv.Msg
		}
		cq.mu.Lock()
		defer cq.mu.Unlock()
		cvl := cq.cache[qname]
		if idx := find(cvl, addr); idx >= 0 {
			if cvl = cq.deleteLocked(cvl, idx); len(cvl) > 0 {
				cq.cache[qname] = cvl
			} else {
				delete(cq.cache, qname)
			}
		}
	}
	return netip.Addr{}, nil
}

func (cq *cacheQtype) clear() {
	cq.clean(time.Time{})
}

func (cq *cacheQtype) clean(now time.Time) {
	cq.mu.Lock()
	defer cq.mu.Unlock()
	for qname, cvl := range cq.cache {
		for i := len(cvl); i > 0; i-- {
			if idx := len(cvl) - 1; idx >= 0 {
				if now.IsZero() || now.After(cvl[idx].expires) {
					cvl = cq.deleteLocked(cvl, idx)
				}
			}
		}
		if len(cvl) > 0 {
			cq.cache[qname] = cvl
		} else {
			delete(cq.cache, qname)
		}
	}
}

func (cq *cacheQtype) deleteLocked(cvl []cacheValue, idx int) []cacheValue {
	l := len(cvl) - 1
	if idx < l {
		cvl[idx], cvl[l] = cvl[l], cvl[idx]
	}
	clear(cvl[l].Msg.Question)
	clear(cvl[l].Msg.Answer)
	clear(cvl[l].Msg.Ns)
	clear(cvl[l].Msg.Extra)
	cvl[l] = cacheValue{}
	return cvl[:l]
}
