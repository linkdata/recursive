package recursive

import (
	"net/netip"
	"sort"
	"time"
)

// Cookie management methods

func (r *Recursive) getClientCookie() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cookies.clientCookie
}

func (r *Recursive) getServerCookie(addr netip.Addr) (string, bool) {
	now := time.Now()
	r.cleanupServerCookies(now)

	r.mu.RLock()
	c, ok := r.cookies.serverCookies[addr]
	r.mu.RUnlock()

	if ok && now.Sub(c.ts) < srvCookieTTL {
		return c.value, true
	}
	return "", false
}

func (r *Recursive) setServerCookie(addr netip.Addr, val string) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupServerCookiesLocked(now)
	r.cookies.serverCookies[addr] = srvCookie{value: val, ts: now}
}

func (r *Recursive) cleanupServerCookies(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupServerCookiesLocked(now)
}

func (r *Recursive) cleanupServerCookiesLocked(now time.Time) {
	// Remove expired cookies
	cutoff := now.Add(-srvCookieTTL)
	for addr, c := range r.cookies.serverCookies {
		if c.ts.Before(cutoff) {
			delete(r.cookies.serverCookies, addr)
		}
	}

	// Limit total number of cookies
	if len(r.cookies.serverCookies) <= maxSrvCookies {
		return
	}

	// Remove oldest cookies if we have too many
	type addrCookie struct {
		addr netip.Addr
		ts   time.Time
	}

	cookies := make([]addrCookie, 0, len(r.cookies.serverCookies))
	for addr, c := range r.cookies.serverCookies {
		cookies = append(cookies, addrCookie{addr: addr, ts: c.ts})
	}

	sort.Slice(cookies, func(i, j int) bool {
		return cookies[i].ts.Before(cookies[j].ts)
	})

	for i := 0; len(r.cookies.serverCookies) > maxSrvCookies && i < len(cookies); i++ {
		delete(r.cookies.serverCookies, cookies[i].addr)
	}
}
