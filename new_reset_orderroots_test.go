package recursive

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

type fakeDialer struct {
	delays map[string]time.Duration // negative duration means failure
}

func (d *fakeDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *fakeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	delay, ok := d.delays[addr]
	if !ok {
		return nil, errors.New("unexpected address")
	}
	if delay < 0 {
		return nil, errors.New("dial failure")
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func TestNewCallsOrderRoots(t *testing.T) {
	fast := netip.MustParseAddr("192.0.2.1")
	slow := netip.MustParseAddr("192.0.2.2")
	fail := netip.MustParseAddr("192.0.2.3")

	d := &fakeDialer{delays: map[string]time.Duration{
		netip.AddrPortFrom(fast, dnsPort).String(): 5 * time.Millisecond,
		netip.AddrPortFrom(slow, dnsPort).String(): 25 * time.Millisecond,
		netip.AddrPortFrom(fail, dnsPort).String(): -1,
	}}

	old4, old6 := Roots4, Roots6
	Roots4 = []netip.Addr{fast, slow, fail}
	Roots6 = nil
	t.Cleanup(func() { Roots4, Roots6 = old4, old6 })

	r := New(d)

	want := []netip.Addr{fast, slow}
	if !reflect.DeepEqual(r.rootServers, want) {
		t.Fatalf("rootServers = %v; want %v", r.rootServers, want)
	}
	if !r.useIPv4 || r.useIPv6 {
		t.Fatalf("useIPv4=%v useIPv6=%v", r.useIPv4, r.useIPv6)
	}
}

func TestOrderRoots(t *testing.T) {
	fast4 := netip.MustParseAddr("192.0.2.1")
	fail4 := netip.MustParseAddr("192.0.2.2")
	fast6 := netip.MustParseAddr("2001:db8::1")
	fail6 := netip.MustParseAddr("2001:db8::2")

	d := &fakeDialer{delays: map[string]time.Duration{
		netip.AddrPortFrom(fast4, dnsPort).String(): 5 * time.Millisecond,
		netip.AddrPortFrom(fast6, dnsPort).String(): 15 * time.Millisecond,
		netip.AddrPortFrom(fail4, dnsPort).String(): -1,
		netip.AddrPortFrom(fail6, dnsPort).String(): -1,
	}}

	r := NewWithOptions(d, nil, []netip.Addr{fast4, fail4}, []netip.Addr{fast6, fail6}, nil)
	r.OrderRoots(context.Background())

	want := []netip.Addr{fast4, fast6}
	if !reflect.DeepEqual(r.rootServers, want) {
		t.Fatalf("rootServers = %v; want %v", r.rootServers, want)
	}
	if !r.useIPv4 || !r.useIPv6 {
		t.Fatalf("useIPv4=%v useIPv6=%v", r.useIPv4, r.useIPv6)
	}
}

func TestResetCookies(t *testing.T) {
	r := NewWithOptions(nil, nil, nil, nil, nil)
	r.clicookie = "old"
	r.srvcookies[netip.MustParseAddr("192.0.2.1")] = srvCookie{value: "x", ts: time.Now()}

	r.ResetCookies()

	if r.clicookie == "old" {
		t.Fatalf("clicookie was not reset")
	}
	if len(r.srvcookies) != 0 {
		t.Fatalf("expected srvcookies cleared, got %d", len(r.srvcookies))
	}
}
