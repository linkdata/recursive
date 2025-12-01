package recursive

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/miekg/dns"
)

type cacheValue struct {
	*dns.Msg       // the message (with Zero flag set)
	expires  int64 // expiry Unix time
}

func (cv cacheValue) expiresAt() time.Time {
	return time.Unix(cv.expires, 0)
}

func (cv *cacheValue) MarshalBinary() (b []byte, err error) {
	var buf [4096]byte
	var packed []byte
	if packed, err = cv.PackBuffer(buf[:]); err == nil {
		b = binary.AppendVarint(b, cv.expires)
		b = append(b, packed...)
	}
	return
}

func (cv *cacheValue) UnmarshalBinary(b []byte) (err error) {
	err = io.ErrShortBuffer
	if expiry, n := binary.Varint(b); n > 0 {
		var msg dns.Msg
		if err = msg.Unpack(b[n:]); err == nil {
			cv.Msg = &msg
			cv.expires = expiry
		}
	}
	return
}

func (cv *cacheValue) WriteTo(w io.Writer) (n int64, err error) {
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
}

func (cv *cacheValue) ReadFrom(r io.Reader) (n int64, err error) {
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
