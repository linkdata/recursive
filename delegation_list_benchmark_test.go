package recursive

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

var (
	benchmarkDelegationNames []string
	benchmarkDelegationAddrs []netip.Addr
)

// BenchmarkDelegationLists measures nameserver and address list construction.
func BenchmarkDelegationLists(b *testing.B) {
	zone := "example.net."
	for _, tc := range []struct {
		name            string
		nameCount       int
		glueHosts       int
		duplicates      int
		unrelated       int
		answerDuplicate bool
		sharedAddress   bool
	}{
		{name: "3_names", nameCount: 3, glueHosts: 3, duplicates: 1},
		{name: "13_names", nameCount: 13, glueHosts: 13, duplicates: 1},
		{name: "13_names_repeated", nameCount: 13, glueHosts: 13, duplicates: 2},
		{name: "13_names_no_glue", nameCount: 13, glueHosts: 0, duplicates: 1},
		{name: "13_names_sparse_glue", nameCount: 13, glueHosts: 1, duplicates: 1},
		{name: "13_names_half_glue", nameCount: 13, glueHosts: 6, duplicates: 1},
		{name: "13_names_shared_addr", nameCount: 13, glueHosts: 13, duplicates: 1, sharedAddress: true},
		{name: "3_names_mixed_sections", nameCount: 3, glueHosts: 3, duplicates: 1, unrelated: 12, answerDuplicate: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			msg := new(dns.Msg)
			msg.SetQuestion(zone, dns.TypeNS)
			for i := 0; i < tc.nameCount; i++ {
				name := fmt.Sprintf("ns%d.example.net.", i)
				for j := 0; j < tc.duplicates; j++ {
					ns := &dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS}, Ns: name}
					msg.Ns = append(msg.Ns, ns)
					if tc.answerDuplicate {
						msg.Answer = append(msg.Answer, ns)
					}
					if i < tc.glueHosts {
						addrIndex := i + 1
						if tc.sharedAddress {
							addrIndex = 1
						}
						msg.Extra = append(
							msg.Extra,
							&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, byte(addrIndex))},
							&dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP(fmt.Sprintf("2001:db8::%x", addrIndex))},
						)
					}
				}
			}
			for i := 0; i < tc.unrelated; i++ {
				msg.Ns = append(msg.Ns, &dns.RRSIG{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG}})
			}
			q := &query{Recursive: NewWithOptions(nil, nil, nil, nil, nil)}
			b.Run("extract", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				var names []string
				var addrs []netip.Addr
				for i := 0; i < b.N; i++ {
					q.glue = make(map[string][]netip.Addr)
					names, addrs = q.extractDelegationNS(msg, zone)
				}
				benchmarkDelegationNames = names
				benchmarkDelegationAddrs = addrs
				wantAddrs := tc.glueHosts
				if tc.sharedAddress {
					wantAddrs = 1
				}
				if len(names) != tc.nameCount || len(addrs) != wantAddrs {
					b.Fatalf("got %d names and %d addresses, want %d and %d", len(names), len(addrs), tc.nameCount, wantAddrs)
				}
			})
			b.Run("append_names", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				var names []string
				for i := 0; i < b.N; i++ {
					names = appendZoneNSNames(nil, msg.Ns, zone)
				}
				benchmarkDelegationNames = names
				if len(names) != tc.nameCount {
					b.Fatalf("got %d names, want %d", len(names), tc.nameCount)
				}
			})
			b.Run("append_addrs", func(b *testing.B) {
				dst := make([]netip.Addr, 0, tc.nameCount)
				src := make([]netip.Addr, 0, tc.nameCount)
				for i := 0; i < tc.nameCount; i++ {
					dst = append(dst, netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}))
					if i%2 == 0 {
						src = append(src, dst[i])
					} else {
						src = append(src, netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}))
					}
					if tc.duplicates > 1 {
						src = append(src, src[len(src)-1])
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				var addrs []netip.Addr
				for i := 0; i < b.N; i++ {
					addrs = appendUniqueAddrs(dst, src)
				}
				benchmarkDelegationAddrs = addrs
				if len(addrs) != tc.nameCount+tc.nameCount/2 {
					b.Fatalf("got %d addresses, want %d", len(addrs), tc.nameCount+tc.nameCount/2)
				}
			})
		})
	}
}

// BenchmarkResolveWithManyCachedNS measures a complete warm resolution with 13 delegated nameservers.
func BenchmarkResolveWithManyCachedNS(b *testing.B) {
	cache := NewCache()
	cache.MinTTL = 0
	cache.DnsSet(newResponseMsg("com.", dns.TypeNS, dns.RcodeSuccess, nil,
		[]dns.RR{mustNewTestRR(b, "com. 300 IN NS ns.com.")},
		[]dns.RR{mustNewTestRR(b, "ns.com. 300 IN A 192.0.2.2")}))

	zone := "example.com."
	example := newResponseMsg(zone, dns.TypeNS, dns.RcodeSuccess, nil, nil, nil)
	for i := 1; i <= 13; i++ {
		host := fmt.Sprintf("ns%d.example.com.", i)
		example.Ns = append(example.Ns, mustNewTestRR(b, fmt.Sprintf("%s 300 IN NS %s", zone, host)))
		example.Extra = append(example.Extra,
			mustNewTestRR(b, fmt.Sprintf("%s 300 IN A 192.0.2.%d", host, i+2)),
			mustNewTestRR(b, fmt.Sprintf("%s 300 IN AAAA 2001:db8::%x", host, i+2)))
	}
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
	q := &query{Recursive: rec, cache: cache, glue: make(map[string][]netip.Addr)}
	addrs, _, _, err := q.queryForDelegationWithCachePolicy(ctx, zone,
		[]netip.Addr{netip.MustParseAddr("192.0.2.2")}, zone, nil)
	if err != nil || len(addrs) != 13 {
		b.Fatalf("cached delegation: addresses=%v err=%v", addrs, err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
		if err != nil || msg == nil || len(msg.Answer) != 1 {
			b.Fatalf("cached resolution: msg=%v err=%v", msg, err)
		}
	}
}

// BenchmarkResolveWithMissingGlueNames measures cached resolution of several nameserver owners.
func BenchmarkResolveWithMissingGlueNames(b *testing.B) {
	for _, tc := range []struct {
		name        string
		partialGlue bool
	}{
		{name: "none"},
		{name: "partial", partialGlue: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			rec, cache := newMissingGlueCachedResolver(b)
			zone := "example.com."
			referral := newResponseMsg(zone, dns.TypeNS, dns.RcodeSuccess, nil, nil, nil)
			for i := 1; i <= 3; i++ {
				host := fmt.Sprintf("ns%d.example.net.", i)
				referral.Ns = append(referral.Ns, mustNewTestRR(b, fmt.Sprintf("%s 300 IN NS %s", zone, host)))
				if tc.partialGlue && i == 1 {
					referral.Extra = append(referral.Extra, mustNewTestRR(b, "ns1.example.net. 300 IN A 192.0.2.61"))
				}
				serverNS := newResponseMsg(host, dns.TypeNS, dns.RcodeSuccess, nil,
					[]dns.RR{mustNewTestRR(b, "example.net. 300 IN SOA ns3.example.net. hostmaster.example.net. 1 3600 600 86400 300")}, nil)
				serverNS.Authoritative = true
				cache.DnsSet(serverNS)
				serverA := newResponseMsg(host, dns.TypeA, dns.RcodeSuccess,
					[]dns.RR{mustNewTestRR(b, fmt.Sprintf("%s 300 IN A 192.0.2.%d", host, i+60))}, nil, nil)
				serverA.Authoritative = true
				cache.DnsSet(serverA)
			}
			cache.DnsSet(referral)
			ctx := b.Context()
			q := &query{Recursive: rec, cache: cache, glue: make(map[string][]netip.Addr)}
			addrs, _, _, err := q.queryForDelegationWithCachePolicy(ctx, zone,
				[]netip.Addr{netip.MustParseAddr("192.0.2.2")}, zone, nil)
			if err != nil || len(addrs) != 3 {
				b.Fatalf("missing-glue delegation: addresses=%v err=%v", addrs, err)
			}
			msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
			if err != nil || msg == nil || len(msg.Answer) != 1 {
				b.Fatalf("cached resolution: msg=%v err=%v", msg, err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
				if err != nil || msg == nil || len(msg.Answer) != 1 {
					b.Fatalf("cached resolution: msg=%v err=%v", msg, err)
				}
			}
		})
	}
}
