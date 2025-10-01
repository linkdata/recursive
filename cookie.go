package recursive

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	rand "math/rand/v2"
	"net/netip"
	"sort"
	"time"
)

var crandRead func(b []byte) (n int, err error) = crand.Read

type srvCookie struct {
	value string
	ts    time.Time
}

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
	if len(s) > 5 {
		return "..." + s[len(s)-5:]
	}
	return s
}

// ResetCookies generates a new DNS client cookie and clears the known DNS server cookies.
func (r *Recursive) ResetCookies() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clicookie = makeCookie()
	clear(r.srvcookies)
}

func (r *Recursive) cleanupSrvCookiesLocked(now time.Time) {
	cutoff := now.Add(-srvCookieTTL)
	for addr, c := range r.srvcookies {
		if c.ts.Before(cutoff) {
			delete(r.srvcookies, addr)
		}
	}
	if len(r.srvcookies) <= maxSrvCookies {
		return
	}
	type ac struct {
		addr netip.Addr
		ts   time.Time
	}
	l := make([]ac, 0, len(r.srvcookies))
	for addr, c := range r.srvcookies {
		l = append(l, ac{addr: addr, ts: c.ts})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].ts.Before(l[j].ts) })
	for i := 0; len(r.srvcookies) > maxSrvCookies && i < len(l); i++ {
		delete(r.srvcookies, l[i].addr)
	}
}

func (r *Recursive) cleanupSrvCookies(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupSrvCookiesLocked(now)
}

func (r *Recursive) getSrvCookieLocked(addr netip.Addr) (s string, found bool) {
	c, ok := r.srvcookies[addr]
	if ok && time.Since(c.ts) < srvCookieTTL {
		s = c.value
		found = true
	}
	return
}

func (r *Recursive) setSrvCookie(now time.Time, addr netip.Addr, val string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.srvcookies[addr] = srvCookie{value: val, ts: now}
}
