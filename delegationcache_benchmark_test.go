package recursive

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

type benchmarkDelegationCacher struct{ *Cache }

func (c benchmarkDelegationCacher) DelegationCache() *Cache { return c.Cache }

// BenchmarkResolveWithDelegationProvider measures cached resolution through an explicit provider.
func BenchmarkResolveWithDelegationProvider(b *testing.B) {
	cache := benchmarkDelegationCacher{cachedDelegationFixture(b)}
	rec := NewWithOptions(nil, cache, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []netip.Addr{}, nil)
	rec.Deterministic = true
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
		if err != nil || msg == nil || len(msg.Answer) != 1 {
			b.Fatalf("cached resolution: msg=%v err=%v", msg, err)
		}
	}
}

// BenchmarkResolveWithDelegationProviderParallel measures concurrent cached resolution through a provider.
func BenchmarkResolveWithDelegationProviderParallel(b *testing.B) {
	cache := benchmarkDelegationCacher{cachedDelegationFixture(b)}
	rec := NewWithOptions(nil, cache, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []netip.Addr{}, nil)
	rec.Deterministic = true
	ctx := b.Context()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			msg, _, err := rec.ResolveWithOptions(ctx, cache, nil, "www.example.com.", dns.TypeA)
			if err != nil || msg == nil || len(msg.Answer) != 1 {
				b.Errorf("cached resolution: msg=%v err=%v", msg, err)
				return
			}
		}
	})
}
