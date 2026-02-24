package recursive

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestDnameRecords(t *testing.T) {
	t.Parallel()

	rrs := []dns.RR{}
	build := []string{
		"ExAmPlE.cOm. 3600 IN DNAME target.example.net.",
		"www.example.com. 3600 IN CNAME alias.example.net.",
		"irrelevant.example.com. 3600 IN A 192.0.2.10",
	}
	for _, text := range build {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("failed to build RR %q: %v", text, err)
		}
		rrs = append(rrs, rr)
	}

	records := dnameRecords(rrs, "WWW.EXAMPLE.COM.")

	if len(records) != 2 {
		t.Fatalf("dnameRecords returned %d entries", len(records))
	}
	if _, ok := records[0].(*dns.DNAME); !ok {
		t.Fatalf("expected first record to be DNAME, got %T", records[0])
	}
	if _, ok := records[1].(*dns.CNAME); !ok {
		t.Fatalf("expected second record to be CNAME, got %T", records[1])
	}
}

func TestDnameSynthesizeAtOwner(t *testing.T) {
	t.Parallel()

	rr, err := dns.NewRR("example.com. 3600 IN DNAME target.example.net.")
	if err != nil {
		t.Fatalf("failed to build DNAME RR: %v", err)
	}

	msg := &dns.Msg{Answer: []dns.RR{rr}}
	got := dnameSynthesize(msg, dns.Fqdn("example.com"))
	want := dns.Fqdn("target.example.net")
	if got != want {
		t.Fatalf("dnameSynthesize() = %q, want %q", got, want)
	}
}

func TestQueryForDelegationFallbackUsesZoneForReferralExtraction(t *testing.T) {
	t.Parallel()

	parent := netip.MustParseAddr("192.0.2.1")
	referralAddr := netip.MustParseAddr("192.0.2.53")
	cache := NewCache()

	minimizedRefused := new(dns.Msg)
	minimizedRefused.SetQuestion("example.com.", dns.TypeNS)
	minimizedRefused.Rcode = dns.RcodeRefused
	cache.DnsSet(minimizedRefused)

	fallbackReferral := new(dns.Msg)
	fallbackReferral.SetQuestion("www.example.com.", dns.TypeNS)
	fallbackReferral.Rcode = dns.RcodeSuccess

	ns, err := dns.NewRR("example.com. 3600 IN NS ns1.example.net.")
	if err != nil {
		t.Fatalf("failed to build NS record: %v", err)
	}
	a, err := dns.NewRR("ns1.example.net. 3600 IN A 192.0.2.53")
	if err != nil {
		t.Fatalf("failed to build A record: %v", err)
	}
	fallbackReferral.Ns = []dns.RR{ns}
	fallbackReferral.Extra = []dns.RR{a}
	cache.DnsSet(fallbackReferral)

	rec := NewWithOptions(nil, cache, []netip.Addr{parent}, nil, nil)
	q := &query{Recursive: rec, cache: cache, glue: make(map[string][]netip.Addr)}

	addrs, resp, _, err := q.queryForDelegation(context.Background(), "example.com.", []netip.Addr{parent}, "www.example.com.")
	if err != nil {
		t.Fatalf("queryForDelegation returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("queryForDelegation returned nil response")
	}
	if len(addrs) != 1 || addrs[0] != referralAddr {
		t.Fatalf("unexpected delegation addresses: %#v", addrs)
	}
}

func TestResolveNSAddrsUsesConfiguredAddressFamilies(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	root := netip.MustParseAddr("2001:db8::1")
	nsHost := dns.Fqdn("ns1.example.net")
	ipv4 := net.IPv4(192, 0, 2, 53)
	ipv6 := net.ParseIP("2001:db8::53")

	for _, zone := range []string{dns.Fqdn("net"), dns.Fqdn("example.net"), nsHost} {
		msg := new(dns.Msg)
		msg.SetQuestion(zone, dns.TypeNS)
		msg.Rcode = dns.RcodeSuccess
		msg.Authoritative = true
		cache.DnsSet(msg)
	}

	msgA := new(dns.Msg)
	msgA.SetQuestion(nsHost, dns.TypeA)
	msgA.Rcode = dns.RcodeSuccess
	msgA.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   nsHost,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: ipv4,
		},
	}
	cache.DnsSet(msgA)

	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(nsHost, dns.TypeAAAA)
	msgAAAA.Rcode = dns.RcodeSuccess
	msgAAAA.Answer = []dns.RR{
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   nsHost,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: ipv6,
		},
	}
	cache.DnsSet(msgAAAA)

	rec := NewWithOptions(nil, cache, []netip.Addr{}, []netip.Addr{root}, nil)
	q := &query{Recursive: rec, cache: cache, glue: make(map[string][]netip.Addr)}

	addrs := q.resolveNSAddrs(context.Background(), []string{nsHost})
	if len(addrs) != 1 {
		t.Fatalf("resolveNSAddrs returned %d addrs, want 1", len(addrs))
	}
	if !addrs[0].Is6() {
		t.Fatalf("resolveNSAddrs returned non-IPv6 addr %v in IPv6-only mode", addrs[0])
	}
	if got := addrs[0].String(); got != "2001:db8::53" {
		t.Fatalf("resolveNSAddrs returned %s, want 2001:db8::53", got)
	}
}
