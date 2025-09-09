package recursive

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// newStubRecursive returns a Recursive resolver whose network access is
// replaced by the provided responses. The key in the map is the DNS record
// type to return when queried.
func newStubRecursive(responses map[uint16]*dns.Msg) *Recursive {
	r := &Recursive{}
	r.dnsResolve = func(ctx context.Context, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
		if msg, ok := responses[qtype]; ok {
			m := msg.Copy()
			m.SetQuestion(qname, qtype)
			return m, netip.MustParseAddr("192.0.2.53"), nil
		}
		return nil, netip.Addr{}, nil
	}
	return r
}

func TestLookupFunctionsWithStub(t *testing.T) {
	ipv4 := net.ParseIP("192.0.2.1")
	ipv6 := net.ParseIP("2001:db8::1")

	aMsg := &dns.Msg{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ipv4}}}
	aaaaMsg := &dns.Msg{Answer: []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: ipv6}}}
	nsMsg := &dns.Msg{Answer: []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.org."}}}

	r := newStubRecursive(map[uint16]*dns.Msg{
		dns.TypeA:    aMsg,
		dns.TypeAAAA: aaaaMsg,
		dns.TypeNS:   nsMsg,
	})

	ctx := context.Background()

	ips, err := r.LookupIP(ctx, "ip", "example.org")
	if err != nil || len(ips) != 2 {
		t.Fatalf("LookupIP(ip) = %v, %v", ips, err)
	}
	if !ips[0].Equal(ipv4) && !ips[1].Equal(ipv4) {
		t.Errorf("IPv4 address missing from LookupIP")
	}
	if !ips[0].Equal(ipv6) && !ips[1].Equal(ipv6) {
		t.Errorf("IPv6 address missing from LookupIP")
	}

	ips4, err := r.LookupIP(ctx, "ip4", "example.org")
	if err != nil || len(ips4) != 1 || !ips4[0].Equal(ipv4) {
		t.Fatalf("LookupIP(ip4) = %v, %v", ips4, err)
	}
	ips6, err := r.LookupIP(ctx, "ip6", "example.org")
	if err != nil || len(ips6) != 1 || !ips6[0].Equal(ipv6) {
		t.Fatalf("LookupIP(ip6) = %v, %v", ips6, err)
	}

	hosts, err := r.LookupHost(ctx, "example.org")
	if err != nil || len(hosts) != 2 {
		t.Fatalf("LookupHost = %v, %v", hosts, err)
	}

	netips, err := r.LookupNetIP(ctx, "ip", "example.org")
	if err != nil || len(netips) != 2 {
		t.Fatalf("LookupNetIP = %v, %v", netips, err)
	}

	addrs, err := r.LookupIPAddr(ctx, "example.org")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("LookupIPAddr = %v, %v", addrs, err)
	}

	nslist, err := r.LookupNS(ctx, "example.org")
	if err != nil || len(nslist) != 1 || nslist[0].Host != "ns.example.org." {
		t.Fatalf("LookupNS = %v, %v", nslist, err)
	}
}
