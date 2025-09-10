package recursive

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestDnsTypeToString(t *testing.T) {
	if got := DnsTypeToString(dns.TypeA); got != "A" {
		t.Errorf("DnsTypeToString(TypeA) = %q; want %q", got, "A")
	}
	if got := DnsTypeToString(9999); got != "9999" {
		t.Errorf("DnsTypeToString(9999) = %q; want %q", got, "9999")
	}
}

func TestAddrFromRR(t *testing.T) {
	ipv4 := net.ParseIP("192.0.2.1").To4()
	rrA := &dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: ipv4}
	if got := AddrFromRR(rrA); got != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("AddrFromRR(A) = %v; want %v", got, "192.0.2.1")
	}
	ipv6 := net.ParseIP("2001:db8::1")
	rrAAAA := &dns.AAAA{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: ipv6}
	if got := AddrFromRR(rrAAAA); got != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("AddrFromRR(AAAA) = %v; want %v", got, "2001:db8::1")
	}
	rrNS := &dns.NS{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.example.org."}
	if got := AddrFromRR(rrNS); got.IsValid() {
		t.Errorf("AddrFromRR(NS) = %v; want invalid", got)
	}
}

func TestMinTTL(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.1")},
		&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 20}, A: net.ParseIP("192.0.2.2")},
	}
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 10}, Ns: "ns1.example.org."},
	}
	msg.Extra = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 5}, Ns: "ns2.example.org."},
	}
	if ttl := MinTTL(msg); ttl != 5 {
		t.Errorf("MinTTL() = %d; want 5", ttl)
	}
	empty := new(dns.Msg)
	if ttl := MinTTL(empty); ttl != -1 {
		t.Errorf("MinTTL(empty) = %d; want -1", ttl)
	}
}

func TestMinTTLIgnoresOPT(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.1")},
	}
	msg.Extra = []dns.RR{
		&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}},
	}
	if ttl := MinTTL(msg); ttl != 30 {
		t.Fatalf("MinTTL ignoring OPT = %d; want 30", ttl)
	}
	onlyOpt := new(dns.Msg)
	onlyOpt.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}}}
	if ttl := MinTTL(onlyOpt); ttl != -1 {
		t.Fatalf("MinTTL(onlyOpt) = %d; want -1", ttl)
	}
}

func TestNetError(t *testing.T) {
	inner := errors.New("boom")
	ne := netError{Err: inner}
	if ne.Error() != inner.Error() {
		t.Fatalf("Error() = %q; want %q", ne.Error(), inner.Error())
	}
	if !errors.Is(ne, inner) {
		t.Fatalf("errors.Is failed to unwrap netError")
	}
}
