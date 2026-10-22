package recursive

import (
	"testing"

	"github.com/miekg/dns"
)

func newDefaultRootsCachedBenchmark(b *testing.B, missingGlue bool) (*Recursive, *fixedMissingGlueCacher) {
	b.Helper()
	_, cache := newMissingGlueCachedResolver(b)
	rec := NewWithOptions(nil, cache, nil, nil, nil)
	rec.Deterministic = true
	if !missingGlue {
		cache.DnsSet(newResponseMsg("example.com.", dns.TypeNS, dns.RcodeSuccess, nil,
			[]dns.RR{
				mustNewTestRR(b, "example.com. 300 IN NS ns1.example.com."),
				mustNewTestRR(b, "example.com. 300 IN NS ns2.example.net."),
			},
			[]dns.RR{
				mustNewTestRR(b, "ns1.example.com. 300 IN A 192.0.2.53"),
				mustNewTestRR(b, "ns2.example.net. 300 IN A 192.0.2.54"),
			}))
	}
	if len(rec.rootServers) != 26 {
		b.Fatalf("root count = %d, want 26", len(rec.rootServers))
	}
	msg, _, err := rec.ResolveWithOptions(b.Context(), cache, nil, "www.example.com.", dns.TypeA)
	if err != nil || msg == nil || len(msg.Answer) != 1 {
		b.Fatalf("cached resolution: msg=%v err=%v", msg, err)
	}
	return rec, cache
}

// BenchmarkResolveWithDefaultRootsCached measures full cached resolution with 26 roots.
func BenchmarkResolveWithDefaultRootsCached(b *testing.B) {
	for _, tc := range []struct {
		name        string
		missingGlue bool
	}{
		{name: "full_glue"},
		{name: "missing_glue", missingGlue: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			rec, cache := newDefaultRootsCachedBenchmark(b, tc.missingGlue)
			ctx := b.Context()
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

// BenchmarkResolveWithDefaultRootsCachedParallel measures concurrent cached resolution with 26 roots.
func BenchmarkResolveWithDefaultRootsCachedParallel(b *testing.B) {
	for _, tc := range []struct {
		name        string
		missingGlue bool
	}{
		{name: "full_glue"},
		{name: "missing_glue", missingGlue: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			rec, cache := newDefaultRootsCachedBenchmark(b, tc.missingGlue)
			ctx := b.Context()
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
					if err != nil || msg == nil || len(msg.Answer) != 1 {
						b.Fatalf("cached resolution: msg=%v err=%v", msg, err)
					}
				}
			})
		})
	}
}
