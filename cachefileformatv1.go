package recursive

// routines to read the old cache file format

import (
	"errors"
	"io"

	"github.com/miekg/dns"
)

const cacheQtypeMagic = uint16(0xFE01)

func (cache *Cache) readFromV1(r io.Reader) (n int64, err error) {
	err = nil
	for _, cq := range cache.cq {
		numread, cqerr := cq.readFromV1(r)
		n += numread
		err = errors.Join(err, cqerr)
		if cqerr == io.EOF || errors.Is(cqerr, io.ErrUnexpectedEOF) {
			break
		}
	}
	return
}

/*func (cq *cacheQtype) WriteTo(w io.Writer) (n int64, err error) {
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
}*/

func (cq *cacheQtype) readFromV1(r io.Reader) (n int64, err error) {
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
					numread, valueerr := cv.readFromV1(r)
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

/*func (cv *cacheValue) WriteTo(w io.Writer) (n int64, err error) {
	if err = writeInt64(w, &n, cv.expires); err == nil {
		var packed []byte
		if packed, err = cv.Pack(); err == nil {
			if err = writeInt64(w, &n, int64(len(packed))); err == nil {
				var written int
				written, err = w.Write(packed)
				n += int64(written)
			}
		}
	}
	return
}*/

func (cv *cacheValue) readFromV1(r io.Reader) (n int64, err error) {
	var expiry, packlen int64
	if expiry, err = readInt64(r, &n); err == nil {
		if packlen, err = readInt64(r, &n); err == nil {
			buf := make([]byte, int(packlen)) // #nosec G115
			var numread int
			if numread, err = io.ReadFull(r, buf); err == nil {
				var msg dns.Msg
				if err = msg.Unpack(buf); err == nil {
					cv.Msg = &msg
					cv.expires = expiry
				}
			}
			n += int64(numread)
		}
	}
	return
}
