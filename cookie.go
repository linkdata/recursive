package recursive

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	rand "math/rand/v2"
)

var crandRead func(b []byte) (n int, err error) = crand.Read

func makeCookie() string {
	var b [8]byte
	n, _ := crandRead(b[:])
	x := binary.LittleEndian.Uint64(b[:])
	if n < len(b) {
		x ^= rand.Uint64() // #nosec G404
	}
	return fmt.Sprintf("%016x", x)
}

func maskCookie(s string) string {
	if len(s) > 8 {
		return s[:8] + "..."
	}
	return s
}
