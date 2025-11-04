package recursive

import (
	"encoding/binary"
	"io"
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

func (cq *cacheQtype) set(msg *dns.Msg, ttl time.Duration) {
	qname := msg.Question[0].Name
	expires := time.Now().Add(ttl)
	cq.mu.Lock()
	cq.cache[qname] = cacheValue{Msg: msg, expires: expires}
	cq.mu.Unlock()
}

func (cq *cacheQtype) get(qname string, allowstale bool) *dns.Msg {
	cq.mu.RLock()
	cv := cq.cache[qname]
	cq.mu.RUnlock()
	if cv.Msg != nil {
		if allowstale || time.Since(cv.expires) < 0 {
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

func (cq *cacheQtype) clean(t time.Time) {
	cq.mu.Lock()
	defer cq.mu.Unlock()
	for qname, cv := range cq.cache {
		if t.IsZero() || cv.expires.Before(t) {
			delete(cq.cache, qname)
		}
	}
}

func (cq *cacheQtype) WriteTo(w io.Writer) (n int64, err error) {
	cq.mu.RLock()
	defer cq.mu.RUnlock()
	var written int
	if written, err = w.Write(binary.BigEndian.AppendUint64(nil, uint64(len(cq.cache)))); err == nil {
		n += int64(written)
		for _, cv := range cq.cache {
			if err == nil {
				var written int64
				written, err = cv.WriteTo(w)
				n += written
			}
		}
	}
	return
}

func (cq *cacheQtype) ReadFrom(r io.Reader) (n int64, err error) {
	cq.mu.Lock()
	defer cq.mu.Unlock()
	clear(cq.cache)
	var numentries uint64
	if err = binary.Read(r, binary.BigEndian, &numentries); err == nil {
		n += 8
		for range numentries {
			if err == nil {
				var cv cacheValue
				var x int64
				if x, err = cv.ReadFrom(r); err == nil {
					cq.cache[cv.Question[0].Name] = cv
				}
				n += x
			}
		}
	}
	return
}
