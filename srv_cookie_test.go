package recursive

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestSrvCookieCleanup(t *testing.T) {
	r := NewWithOptions(nil, nil, nil, nil, nil)
	expiredAddr := netip.MustParseAddr("2001:db8::1")
	r.srvcookies[expiredAddr] = srvCookie{value: "old", ts: time.Now().Add(-srvCookieTTL - time.Minute)}
	for i := 0; i < maxSrvCookies+10; i++ {
		addr := netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i+2))
		r.srvcookies[addr] = srvCookie{value: "new", ts: time.Now()}
	}
	r.cleanupSrvCookies(time.Now())
	if _, ok := r.srvcookies[expiredAddr]; ok {
		t.Fatalf("expired cookie was not pruned")
	}
	if len(r.srvcookies) > maxSrvCookies {
		t.Fatalf("expected at most %d cookies, got %d", maxSrvCookies, len(r.srvcookies))
	}
}
