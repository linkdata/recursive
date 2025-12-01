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
