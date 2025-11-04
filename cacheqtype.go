package recursive

import (
	"fmt"
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

const cacheQtypeMagic = uint16(0xFE01)

func (cq *cacheQtype) WriteTo(w io.Writer) (n int64, err error) {
	cq.mu.RLock()
	defer cq.mu.RUnlock()
	if err = writeUint16(w, &n, cacheQtypeMagic); err == nil {
		numentries := int64(len(cq.cache))
		if numentries > 0 {
			fmt.Println("write", numentries)
		}
		if err = writeInt64(w, &n, numentries); err == nil {
			for _, cv := range cq.cache {
				if err == nil {
					var written int64
					written, err = cv.WriteTo(w)
					n += written
				}
			}
		}
	}
	return
}

func (cq *cacheQtype) ReadFrom(r io.Reader) (n int64, err error) {
	cq.mu.Lock()
	defer cq.mu.Unlock()
	clear(cq.cache)
	var gotmagic uint16
	if gotmagic, err = readUint16(r, &n); err == nil {
		err = ErrWrongMagic
		if gotmagic == cacheQtypeMagic {
			var numentries int64
			if numentries, err = readInt64(r, &n); err == nil {
				if numentries > 0 {
					fmt.Println("read", numentries)
				}
				for range numentries {
					if err == nil {
						var cv cacheValue
						var numread int64
						if numread, err = cv.ReadFrom(r); err == nil {
							err = ErrBadRecord
							if len(cv.Question) > 0 {
								err = nil
								qname := cv.Question[0].Name
								cq.cache[qname] = cv
							}
						}
						n += numread
					}
				}
			}
		}
	}
	return
}
