package recursive

import (
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"

	"github.com/miekg/dns"
)

func TestMaybeDisableIPv6PreservesPublishedRoots(t *testing.T) {
	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := netip.MustParseAddr("2001:db8::1")
	r := &Recursive{useIPv4: true, useIPv6: true, rootServers: []netip.Addr{ip6, ip4}}
	borrowed := r.rootServers

	if !r.maybeDisableIPv6(syscall.ENETUNREACH) {
		t.Fatal("IPv6 was not disabled")
	}
	if !slices.Equal(borrowed, []netip.Addr{ip6, ip4}) {
		t.Fatalf("borrowed root list changed: %v", borrowed)
	}
	if !slices.Equal(r.rootServers, []netip.Addr{ip4}) {
		t.Fatalf("current root list = %v, want [%v]", r.rootServers, ip4)
	}
}

func TestResolveWhileDisablingIPv6(t *testing.T) {
	rec, cache := newMissingGlueCachedResolver(t)
	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := netip.MustParseAddr("2001:db8::1")
	rec.rootServers = []netip.Addr{ip6, ip4}
	blocking := &firstGetBlockingCacher{
		Cacher:  cache,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	result := make(chan struct {
		msg *dns.Msg
		err error
	}, 1)
	ctx := t.Context()
	go func() {
		msg, _, err := rec.ResolveWithOptions(ctx, blocking, nil, "www.example.com.", dns.TypeA)
		result <- struct {
			msg *dns.Msg
			err error
		}{msg, err}
	}()
	<-blocking.entered // queryDelegation has borrowed the roots and reached its first cache lookup
	borrowed := rec.rootServers
	disabled := rec.maybeDisableIPv6(syscall.ENETUNREACH)
	preserved := slices.Equal(borrowed, []netip.Addr{ip6, ip4})
	close(blocking.release)
	got := <-result
	if !disabled || !preserved {
		t.Fatalf("IPv6 disabled=%v, borrowed roots=%v", disabled, borrowed)
	}
	if got.err != nil || got.msg == nil || len(got.msg.Answer) != 1 {
		t.Fatalf("cached resolution: msg=%v err=%v", got.msg, got.err)
	}
}

type firstGetBlockingCacher struct {
	Cacher
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *firstGetBlockingCacher) DnsGet(name string, typ uint16) *dns.Msg {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.Cacher.DnsGet(name, typ)
}
