package recursive

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// BenchmarkQueryForDelegationCached measures a first-parent cache hit.
func BenchmarkQueryForDelegationCached(b *testing.B) {
	zone := "example.com."
	nsOwner := "ns.example.com."
	wantAddr := netip.MustParseAddr("192.0.2.53")
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeNS)
	msg.Zero = true
	msg.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  nsOwner,
	}}
	msg.Extra = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: nsOwner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IP(wantAddr.AsSlice()),
	}}

	parents := append(append([]netip.Addr(nil), Roots4...), Roots6...)
	duplicates := append(append([]netip.Addr(nil), Roots4...), Roots4...)
	for _, tc := range []struct {
		name    string
		parents []netip.Addr
	}{
		{name: "26_unique", parents: parents},
		{name: "26_with_duplicates", parents: duplicates},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cache := &recordingCacher{msg: msg}
			q := &query{
				Recursive: NewWithOptions(nil, nil, nil, nil, nil),
				cache:     cache,
				glue:      make(map[string][]netip.Addr),
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				addrs, resp, srv, err := q.queryForDelegationWithCachePolicy(b.Context(), zone, tc.parents, zone, nil)
				if err != nil || resp != msg || srv != tc.parents[0] || len(addrs) != 1 || addrs[0] != wantAddr {
					b.Fatalf("unexpected delegation: addrs=%v resp=%p srv=%v err=%v", addrs, resp, srv, err)
				}
			}
		})
	}
}

// BenchmarkQueryForDelegationUnavailable measures a full parent-server scan.
//
// Both address families are disabled, so the scan ends without network I/O.
func BenchmarkQueryForDelegationUnavailable(b *testing.B) {
	zone := "example.com."
	parents := append(append([]netip.Addr(nil), Roots4...), Roots6...)
	duplicates := append(append([]netip.Addr(nil), Roots4...), Roots4...)
	for _, tc := range []struct {
		name    string
		parents []netip.Addr
	}{
		{name: "26_unique", parents: parents},
		{name: "26_with_duplicates", parents: duplicates},
	} {
		b.Run(tc.name, func(b *testing.B) {
			q := &query{Recursive: NewWithOptions(nil, nil, []netip.Addr{}, []netip.Addr{}, nil)}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				addrs, resp, srv, err := q.queryForDelegationWithCachePolicy(b.Context(), zone, tc.parents, zone, nil)
				if !errors.Is(err, ErrNoResponse) || resp != nil || len(addrs) != 0 || srv != tc.parents[len(tc.parents)-1] {
					b.Fatalf("unexpected delegation: addrs=%v resp=%p srv=%v err=%v", addrs, resp, srv, err)
				}
			}
		})
	}
}
