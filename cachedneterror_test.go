package recursive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
)

func TestSetNetErrorRecords(t *testing.T) {
	r := &Recursive{
		udperrs: make(map[netip.Addr]*CachedNetError),
		tcperrs: make(map[netip.Addr]*CachedNetError),
	}

	addr6 := netip.MustParseAddr("2001:db8::1")
	is6, isUdp := r.setNetError("udp", addr6, io.EOF)
	if !is6 || !isUdp {
		t.Fatalf("unexpected flags: ipv6=%v udp=%v", is6, isUdp)
	}
	if _, ok := r.udperrs[addr6]; !ok {
		t.Fatalf("expected udp error recorded for %v", addr6)
	}

	addr4 := netip.MustParseAddr("192.0.2.1")
	is6, isUdp = r.setNetError("tcp", addr4, context.DeadlineExceeded)
	if is6 || isUdp {
		t.Fatalf("unexpected flags for tcp ipv4: ipv6=%v udp=%v", is6, isUdp)
	}
	if _, ok := r.tcperrs[addr4]; !ok {
		t.Fatalf("expected tcp error recorded for %v", addr4)
	}

	addrTimeout := netip.MustParseAddr("192.0.2.2")
	is6, isUdp = r.setNetError("udp", addrTimeout, errors.New("i/o timeout"))
	if is6 || !isUdp {
		t.Fatalf("unexpected flags for timeout: ipv6=%v udp=%v", is6, isUdp)
	}
	if _, ok := r.udperrs[addrTimeout]; !ok {
		t.Fatalf("expected udp timeout recorded for %v", addrTimeout)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestMaybeDisableIPv6(t *testing.T) {
	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := netip.MustParseAddr("2001:db8::1")
	r := &Recursive{useIPv4: true, useIPv6: true, rootServers: []netip.Addr{ip4, ip6}}

	r.maybeDisableIPv6(syscall.ENETUNREACH)
	if r.usingIPv6() {
		t.Fatalf("expected IPv6 to be disabled")
	}
	if r.useIPv6 {
		t.Fatalf("IPv6 still enabled")
	}
	if len(r.rootServers) != 1 || r.rootServers[0] != ip4 {
		t.Fatalf("IPv6 root not removed: %v", r.rootServers)
	}
}

func TestMaybeDisableIPv6String(t *testing.T) {
	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := netip.MustParseAddr("2001:db8::1")
	r := &Recursive{useIPv4: true, useIPv6: true, rootServers: []netip.Addr{ip4, ip6}}

	r.maybeDisableIPv6(errors.New("no route to host"))
	if r.usingIPv6() {
		t.Fatalf("expected IPv6 to be disabled on string error")
	}
	if r.useIPv6 {
		t.Fatalf("IPv6 still enabled")
	}
	if len(r.rootServers) != 1 || r.rootServers[0] != ip4 {
		t.Fatalf("IPv6 root not removed: %v", r.rootServers)
	}
}

func TestMaybeDisableUdp(t *testing.T) {
	r := &Recursive{useUDP: true}
	err := &net.OpError{Op: "dial", Net: "udp", Err: syscall.ENOSYS}
	r.maybeDisableUdp(err)
	if r.usingUDP() {
		t.Fatalf("expected UDP to be disabled")
	}
	if r.useUDP {
		t.Fatalf("UDP still enabled")
	}
}

func TestMaybeDisableUdpString(t *testing.T) {
	r := &Recursive{useUDP: true}
	err := &net.OpError{Op: "dial", Net: "udp", Err: errors.New("network not implemented")}
	r.maybeDisableUdp(err)
	if r.usingIPv6() {
		t.Fatalf("expected UDP to be disabled on string error")
	}
	if r.useUDP {
		t.Fatalf("UDP still enabled")
	}
}

func TestMaybeDisableUdpTimeout(t *testing.T) {
	r := &Recursive{useUDP: true}
	err := &net.OpError{Op: "dial", Net: "udp", Err: timeoutErr{}}
	r.maybeDisableUdp(err)
	if !r.usingUDP() {
		t.Fatalf("UDP disabled on timeout error")
	}
	if !r.useUDP {
		t.Fatalf("UDP unexpectedly disabled")
	}
}

func TestCachedNetErrorErrorString(t *testing.T) {
	t.Parallel()

	base := errors.New("network unreachable")
	ne := &CachedNetError{Err: base}

	if got := ne.Error(); !strings.Contains(got, base.Error()) {
		t.Fatalf("Error() = %q does not contain %q", got, base.Error())
	}
	if !errors.Is(ne, base) {
		t.Fatalf("netError does not unwrap to base error")
	}
}
