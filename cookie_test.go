package recursive

import (
	"encoding/binary"
	"net/netip"
	"time"

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
	want := "...bcdef"
	if got := maskCookie(full); got != want {
		t.Errorf("maskCookie(%q) = %q; want %q", full, got, want)
	}
	short := "abcd"
	if got := maskCookie(short); got != short {
		t.Errorf("maskCookie(%q) = %q; want %q", short, got, short)
	}
}

func TestServiceResetCookies(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("192.0.2.1")
	svc := &Recursive{
		clicookie:  "deadbeefdeadbeef",
		srvcookies: map[netip.Addr]srvCookie{addr: {value: "value", ts: time.Now()}},
	}

	svc.ResetCookies()

	if svc.clicookie == "" || svc.clicookie == "deadbeefdeadbeef" {
		t.Fatalf("ResetCookies did not refresh client cookie: %q", svc.clicookie)
	}
	if len(svc.srvcookies) != 0 {
		t.Fatalf("ResetCookies did not clear server cookies: %d", len(svc.srvcookies))
	}
}

func TestCleanupSrvCookiesLocked(t *testing.T) {
	t.Parallel()

	now := time.Now()
	expiredAddr := netip.MustParseAddr("192.0.2.2")
	freshAddr := netip.MustParseAddr("192.0.2.3")
	svc := &Recursive{srvcookies: make(map[netip.Addr]srvCookie)}
	svc.srvcookies[expiredAddr] = srvCookie{value: "expired", ts: now.Add(-srvCookieTTL - time.Minute)}
	svc.srvcookies[freshAddr] = srvCookie{value: "fresh", ts: now}

	svc.cleanupSrvCookiesLocked(now)

	if _, ok := svc.srvcookies[expiredAddr]; ok {
		t.Fatalf("expired cookie not removed")
	}
	if _, ok := svc.srvcookies[freshAddr]; !ok {
		t.Fatalf("fresh cookie unexpectedly removed")
	}

	svc.srvcookies = make(map[netip.Addr]srvCookie)
	var firstAddr netip.Addr
	var lastAddr netip.Addr
	for i := 0; i <= maxSrvCookies; i++ {
		var octets [4]byte
		binary.BigEndian.PutUint32(octets[:], uint32(i+1))
		addr := netip.AddrFrom4(octets)
		if i == 0 {
			firstAddr = addr
		}
		if i == maxSrvCookies {
			lastAddr = addr
		}
		svc.srvcookies[addr] = srvCookie{value: "cookie", ts: now.Add(time.Duration(i) * time.Second)}
	}

	svc.cleanupSrvCookiesLocked(now)

	if len(svc.srvcookies) != maxSrvCookies {
		t.Fatalf("expected %d cookies after trim, got %d", maxSrvCookies, len(svc.srvcookies))
	}
	if _, ok := svc.srvcookies[firstAddr]; ok {
		t.Fatalf("oldest cookie not trimmed")
	}
	if _, ok := svc.srvcookies[lastAddr]; !ok {
		t.Fatalf("newest cookie trimmed")
	}
}
