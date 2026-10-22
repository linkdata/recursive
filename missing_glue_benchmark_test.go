package recursive

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// fixedMissingGlueCacher returns immutable cached replies without TTL copying.
type fixedMissingGlueCacher struct {
	replies map[bucketKey]*dns.Msg
}

func (c *fixedMissingGlueCacher) DnsSet(msg *dns.Msg) {
	if msg != nil && len(msg.Question) == 1 {
		copy := msg.Copy()
		copy.Zero = true
		c.replies[questionBucketKey(copy.Question[0])] = copy
	}
}

func (c *fixedMissingGlueCacher) DnsGet(name string, typ uint16) *dns.Msg {
	return c.replies[newBucketKey(name, typ)]
}

func newMissingGlueBenchmarkResolver(b *testing.B) (*Recursive, *fixedMissingGlueCacher) {
	b.Helper()
	cache := &fixedMissingGlueCacher{replies: make(map[bucketKey]*dns.Msg)}
	addReply := func(name string, typ uint16, authoritative bool, answer, authority, extra []string) {
		b.Helper()
		msg := new(dns.Msg)
		msg.SetQuestion(name, typ)
		msg.Authoritative = authoritative
		for _, section := range []struct {
			records []string
			dst     *[]dns.RR
		}{
			{answer, &msg.Answer},
			{authority, &msg.Ns},
			{extra, &msg.Extra},
		} {
			for _, record := range section.records {
				rr, err := dns.NewRR(record)
				if err != nil {
					b.Fatalf("parse DNS record %q: %v", record, err)
				}
				*section.dst = append(*section.dst, rr)
			}
		}
		cache.DnsSet(msg)
	}

	addReply("com.", dns.TypeNS, false, nil,
		[]string{"com. 300 IN NS ns.com."},
		[]string{"ns.com. 300 IN A 192.0.2.2"})
	addReply("example.com.", dns.TypeNS, false, nil,
		[]string{
			"example.com. 300 IN NS ns1.example.com.",
			"example.com. 300 IN NS ns2.example.net.",
		},
		[]string{"ns1.example.com. 300 IN A 192.0.2.53"})
	addReply("www.example.com.", dns.TypeNS, true, nil,
		[]string{"example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300"}, nil)
	addReply("www.example.com.", dns.TypeA, true,
		[]string{"www.example.com. 300 IN A 203.0.113.7"}, nil, nil)
	addReply("net.", dns.TypeNS, false, nil,
		[]string{"net. 300 IN NS ns.net."},
		[]string{"ns.net. 300 IN A 192.0.2.3"})
	addReply("example.net.", dns.TypeNS, false, nil,
		[]string{"example.net. 300 IN NS ns3.example.net."},
		[]string{"ns3.example.net. 300 IN A 192.0.2.4"})
	addReply("ns2.example.net.", dns.TypeNS, true, nil,
		[]string{"example.net. 300 IN SOA ns3.example.net. hostmaster.example.net. 1 3600 600 86400 300"}, nil)
	addReply("ns2.example.net.", dns.TypeA, true,
		[]string{"ns2.example.net. 300 IN A 192.0.2.54"}, nil, nil)
	addReply("ns2.example.net.", dns.TypeAAAA, true,
		[]string{"ns2.example.net. 300 IN AAAA 2001:db8::54"}, nil, nil)

	rec := NewWithOptions(nil, cache,
		[]netip.Addr{netip.MustParseAddr("192.0.2.1")},
		[]netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil)
	rec.Deterministic = true
	return rec, cache
}

// BenchmarkResolveMissingGlueDualStackCached measures missing-glue resolution.
//
// It calls ResolveWithOptions with valid cached A and AAAA replies. The fixed
// cache excludes TTL copying and network waits.
func BenchmarkResolveMissingGlueDualStackCached(b *testing.B) {
	rec, cache := newMissingGlueBenchmarkResolver(b)
	ctx := b.Context()
	msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
	if err != nil || msg == nil || len(msg.Answer) != 1 {
		b.Fatalf("resolve: msg=%v err=%v", msg, err)
	}
	answer, ok := msg.Answer[0].(*dns.A)
	if !ok || answer.A.String() != "203.0.113.7" {
		b.Fatalf("unexpected answer: %v", msg.Answer[0])
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
		if err != nil || msg == nil || len(msg.Answer) != 1 {
			b.Fatalf("resolve: msg=%v err=%v", msg, err)
		}
	}
}
