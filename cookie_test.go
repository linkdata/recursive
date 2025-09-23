package recursive

import (
	"encoding/binary"
	rand "math/rand/v2"
	"testing"
)

func init() {
	crandRead = func(b []byte) (n int, err error) {
		binary.LittleEndian.PutUint64(b, rand.Uint64())
		n = len(b) - 1
		return
	}
}

func TestMakeCookie(t *testing.T) {
	cookies := map[string]struct{}{}
	duplicates := 0
	for range 1000 {
		if x := makeCookie(); len(x)%2 != 0 {
			t.Fatal("cookie not an even number of hex digits", x)
		} else {
			if _, ok := cookies[x]; ok {
				duplicates++
			}
			cookies[x] = struct{}{}
		}
	}
	if duplicates > 0 {
		t.Log(duplicates, "duplicates")
		if duplicates > 10 {
			t.Fatal("too many duplicates")
		}
	}
}

func TestMaskCookie(t *testing.T) {
	full := "1234567890abcdef"
	if got := maskCookie(full); got != "12345678..." {
		t.Errorf("maskCookie(%q) = %q; want %q", full, got, "12345678...")
	}
	short := "abcd"
	if got := maskCookie(short); got != short {
		t.Errorf("maskCookie(%q) = %q; want %q", short, got, short)
	}
}
