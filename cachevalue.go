package recursive

import (
	"errors"
	"io"
	"time"

	"github.com/miekg/dns"
)

type cacheValue struct {
	*dns.Msg
	expires time.Time
}

var ErrBadRecord = errors.New("bad record")

func (cv *cacheValue) WriteTo(w io.Writer) (n int64, err error) {
	if err = writeInt64(w, &n, cv.expires.UnixMilli()); err == nil {
		var packed []byte
		if packed, err = cv.Pack(); err == nil {
			err = ErrBadRecord
			if packlen := int64(len(packed)); packlen < 1<<16 {
				if err = writeInt64(w, &n, packlen); err == nil {
					var written int
					if written, err = w.Write(packed); err == nil {
						err = ErrBadRecord
						if written == len(packed) {
							err = nil
						}
					}
					n += int64(written)
				}
			}
		}
	}
	return
}

func (cv *cacheValue) ReadFrom(r io.Reader) (n int64, err error) {
	var expiry, packlen int64
	if expiry, err = readInt64(r, &n); err == nil {
		expires := time.UnixMilli(expiry)
		if packlen, err = readInt64(r, &n); err == nil {
			buf := make([]byte, int(packlen)) // #nosec G115
			var numread int
			if numread, err = io.ReadFull(r, buf); err == nil {
				var msg dns.Msg
				if err = msg.Unpack(buf); err == nil {
					cv.Msg = &msg
					cv.expires = expires
				}
			}
			n += int64(numread)
		}
	}
	return
}
