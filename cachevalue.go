package recursive

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/miekg/dns"
)

type cacheValue struct {
	*dns.Msg
	expires time.Time
}

func (cv *cacheValue) WriteTo(w io.Writer) (n int64, err error) {
	var packed, b []byte
	if packed, err = cv.Pack(); err == nil {
		expiry := uint64(cv.expires.UnixMilli()) // #nosec G115
		packlen := uint64(len(packed))
		b = binary.BigEndian.AppendUint64(b, expiry)
		b = binary.BigEndian.AppendUint64(b, packlen)
		b = append(b, packed...)
		var written int
		written, err = w.Write(b)
		n += int64(written)
	}
	return
}

func (cv *cacheValue) ReadFrom(r io.Reader) (n int64, err error) {
	var expiry, packlen uint64
	if err = binary.Read(r, binary.BigEndian, &expiry); err == nil {
		n += 8
		if err = binary.Read(r, binary.BigEndian, &packlen); err == nil {
			n += 8
			buf := make([]byte, int(packlen)) // #nosec G115
			var numread int
			if numread, err = r.Read(buf); err == nil {
				var msg dns.Msg
				if err = msg.Unpack(buf); err == nil {
					cv.Msg = &msg
					cv.expires = time.UnixMilli(int64(expiry)) // #nosec G115
				}
			}
			n += int64(numread)
		}
	}
	return
}
