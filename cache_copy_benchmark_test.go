package recursive

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// BenchmarkCacheDnsGetDelegation measures cache hits for an NS reply with IPv4 and IPv6 glue.
func BenchmarkCacheDnsGetDelegation(b *testing.B) {
	const zone = "example.org."
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeNS)
	for i, last := range []byte{1, 2, 3, 4} {
		host := fmt.Sprintf("ns%d.example.org.", i+1)
		msg.Ns = append(msg.Ns, &dns.NS{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
			Ns:  host,
		})
		msg.Extra = append(
			msg.Extra,
			&dns.A{
				Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(192, 0, 2, last),
			},
			&dns.AAAA{
				Hdr:  dns.RR_Header{Name: host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP(fmt.Sprintf("2001:db8::%d", last)),
			},
		)
	}
	msg.Extra = append(msg.Extra, &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
	})

	for _, tc := range []struct {
		name   string
		minTTL uint32
		clamp  bool
	}{
		{name: "clamp", minTTL: 0, clamp: true},
		{name: "no_clamp", minTTL: 600},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cache := NewCache()
			cache.MinTTL = tc.minTTL
			cache.DnsSet(msg)
			cached := cache.DnsGet(zone, dns.TypeNS)
			if cached == nil {
				b.Fatal("cached delegation missing")
			}
			if (cached.Ns[0].Header().Ttl < 300) != tc.clamp {
				b.Fatalf("unexpected TTL %d for clamp=%t", cached.Ns[0].Header().Ttl, tc.clamp)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if cache.DnsGet(zone, dns.TypeNS) == nil {
					b.Fatal("cached delegation missing")
				}
			}
		})
	}
}

// BenchmarkResolveWithCachedDelegation measures a warm resolution through real cache entries.
func BenchmarkResolveWithCachedDelegation(b *testing.B) {
	cache := NewCache()
	cache.MinTTL = 0
	com := newResponseMsg("com.", dns.TypeNS, dns.RcodeSuccess, nil,
		[]dns.RR{mustNewTestRR(b, "com. 300 IN NS ns.com.")},
		[]dns.RR{mustNewTestRR(b, "ns.com. 300 IN A 192.0.2.2")})
	cache.DnsSet(com)
	example := newResponseMsg("example.com.", dns.TypeNS, dns.RcodeSuccess, nil,
		[]dns.RR{mustNewTestRR(b, "example.com. 300 IN NS ns1.example.com.")},
		[]dns.RR{mustNewTestRR(b, "ns1.example.com. 300 IN A 192.0.2.53")})
	cache.DnsSet(example)
	auth := newResponseMsg("www.example.com.", dns.TypeNS, dns.RcodeSuccess,
		[]dns.RR{mustNewTestRR(b, "www.example.com. 300 IN NS ns1.www.example.com.")}, nil,
		[]dns.RR{mustNewTestRR(b, "ns1.www.example.com. 300 IN A 192.0.2.54")})
	auth.Authoritative = true
	cache.DnsSet(auth)
	answer := newResponseMsg("www.example.com.", dns.TypeA, dns.RcodeSuccess,
		[]dns.RR{mustNewTestRR(b, "www.example.com. 300 IN A 203.0.113.7")}, nil, nil)
	answer.Authoritative = true
	cache.DnsSet(answer)

	rec := NewWithOptions(nil, cache, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []netip.Addr{}, nil)
	rec.Deterministic = true
	ctx := b.Context()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
		if err != nil || msg == nil || len(msg.Answer) != 1 {
			b.Fatalf("cached resolution: msg=%v err=%v", msg, err)
		}
	}
}

// BenchmarkCacheDnsGetAddress measures cache hits for A and AAAA replies.
func BenchmarkCacheDnsGetAddress(b *testing.B) {
	const host = "ns.example.org."
	for _, tc := range []struct {
		name  string
		qtype uint16
		rr    dns.RR
	}{
		{
			name:  "A",
			qtype: dns.TypeA,
			rr: &dns.A{
				Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(192, 0, 2, 1),
			},
		},
		{
			name:  "AAAA",
			qtype: dns.TypeAAAA,
			rr: &dns.AAAA{
				Hdr:  dns.RR_Header{Name: host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::1"),
			},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			msg := new(dns.Msg)
			msg.SetQuestion(host, tc.qtype)
			msg.Answer = []dns.RR{tc.rr}
			msg.Extra = []dns.RR{&dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
			}}
			for _, ttlCase := range []struct {
				name   string
				minTTL uint32
				clamp  bool
			}{
				{name: "clamp", minTTL: 0, clamp: true},
				{name: "no_clamp", minTTL: 600},
			} {
				b.Run(ttlCase.name, func(b *testing.B) {
					cache := NewCache()
					cache.MinTTL = ttlCase.minTTL
					cache.DnsSet(msg)
					cached := cache.DnsGet(host, tc.qtype)
					if cached == nil {
						b.Fatal("cached address missing")
					}
					if (cached.Answer[0].Header().Ttl < 300) != ttlCase.clamp {
						b.Fatalf("unexpected TTL %d for clamp=%t", cached.Answer[0].Header().Ttl, ttlCase.clamp)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if cache.DnsGet(host, tc.qtype) == nil {
							b.Fatal("cached address missing")
						}
					}
				})
			}
		})
	}
}
