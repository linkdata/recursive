package recursive

import (
	"errors"
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

func (cq *cacheQtype) get(qname string, allowstale bool) (msg *dns.Msg, stale bool) {
	cq.mu.RLock()
	cv := cq.cache[qname]
	cq.mu.RUnlock()
	if cv.Msg != nil {
		stale = time.Since(cv.expires) > 0
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
		if err = writeInt64(w, &n, numentries); err == nil {
			for _, cv := range cq.cache {
				written, valueerr := cv.WriteTo(w)
				n += written
				err = errors.Join(err, valueerr)
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
				for range numentries {
					var cv cacheValue
					numread, valueerr := cv.ReadFrom(r)
					n += numread
					if valueerr == nil {
						qname := cv.Question[0].Name
						cq.cache[qname] = cv
					} else {
						err = errors.Join(err, valueerr)
						if valueerr == io.EOF || errors.Is(valueerr, io.ErrUnexpectedEOF) {
							break
						}
					}
				}
			}
		}
	}
	return
}
