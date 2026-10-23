package recursive

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

func TestAppendZoneNSNames(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		dst     []string
		records []string
		want    []string
	}{
		{
			name: "no matching NS",
			records: []string{
				"other.example. 300 IN NS ns.other.example.",
				"example.com. 300 IN A 192.0.2.1",
			},
		},
		{
			name: "first seen order and case fold",
			dst:  []string{"ns0.example.net."},
			records: []string{
				"EXAMPLE.COM. 300 IN NS NS2.EXAMPLE.NET.",
				"example.com. 300 IN NS ns1.example.net.",
				"example.com. 300 IN NS ns2.example.net.",
				"other.com. 300 IN NS ns3.example.net.",
			},
			want: []string{"ns0.example.net.", "ns2.example.net.", "ns1.example.net."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var records []dns.RR
			for _, record := range tc.records {
				records = append(records, mustNewTestRR(t, record))
			}
			got := appendZoneNSNames(tc.dst, records, "example.com.")
			if !slices.Equal(got, tc.want) || (got == nil) != (tc.want == nil) {
				t.Fatalf("appendZoneNSNames() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQueryForDelegationMissingGlueList(t *testing.T) {
	t.Parallel()
	shared := netip.MustParseAddr("192.0.2.61")
	for _, tc := range []struct {
		name string
		ips  []string
		want []netip.Addr
	}{
		{name: "distinct", ips: []string{"192.0.2.61", "192.0.2.62"}, want: []netip.Addr{shared, netip.MustParseAddr("192.0.2.62")}},
		{name: "shared address", ips: []string{"192.0.2.61", "192.0.2.61"}, want: []netip.Addr{shared}},
		{name: "unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec, cache := newMissingGlueCachedResolver(t)
			zone := "example.com."
			hosts := []string{"ns1.example.net.", "ns2.example.net."}
			referral := newResponseMsg(zone, dns.TypeNS, dns.RcodeSuccess, nil, nil, nil)
			for _, host := range hosts {
				referral.Ns = append(referral.Ns, mustNewTestRR(t, zone+" 300 IN NS "+host))
			}
			cache.DnsSet(referral)
			for i, host := range hosts {
				serverNS := newResponseMsg(host, dns.TypeNS, dns.RcodeSuccess, nil,
					[]dns.RR{mustNewTestRR(t, "example.net. 300 IN SOA ns3.example.net. hostmaster.example.net. 1 3600 600 86400 300")}, nil)
				serverNS.Authoritative = true
				cache.DnsSet(serverNS)
				var serverA *dns.Msg
				if i < len(tc.ips) {
					serverA = newResponseMsg(host, dns.TypeA, dns.RcodeSuccess,
						[]dns.RR{mustNewTestRR(t, host+" 300 IN A "+tc.ips[i])}, nil, nil)
				} else {
					serverA = newResponseMsg(host, dns.TypeA, dns.RcodeNameError, nil,
						[]dns.RR{mustNewTestRR(t, "example.net. 300 IN SOA ns3.example.net. hostmaster.example.net. 1 3600 600 86400 300")}, nil)
				}
				serverA.Authoritative = true
				cache.DnsSet(serverA)
				serverAAAA := newResponseMsg(host, dns.TypeAAAA, dns.RcodeNameError, nil,
					[]dns.RR{mustNewTestRR(t, "example.net. 300 IN SOA ns3.example.net. hostmaster.example.net. 1 3600 600 86400 300")}, nil)
				serverAAAA.Authoritative = true
				cache.DnsSet(serverAAAA)
			}
			q := &query{Recursive: rec, cache: cache, glue: make(map[string][]netip.Addr)}
			addrs, resp, _, err := q.queryForDelegation(t.Context(), zone,
				[]netip.Addr{netip.MustParseAddr("192.0.2.2")}, zone)
			if err != nil || resp == nil || len(resp.Ns) != len(hosts) {
				t.Fatalf("queryForDelegation: addresses=%v response=%v err=%v", addrs, resp, err)
			}
			for i, rr := range resp.Ns {
				ns, ok := rr.(*dns.NS)
				if !ok || ns.Ns != hosts[i] {
					t.Fatalf("parent referral record %d = %v, want %s", i, rr, hosts[i])
				}
			}
			if !slices.Equal(addrs, tc.want) {
				t.Fatalf("queryForDelegation addresses = %v, want %v", addrs, tc.want)
			}
		})
	}
}
