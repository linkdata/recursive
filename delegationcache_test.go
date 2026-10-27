package recursive

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

type delegationTestCacher struct {
	*Cache
	provide       bool
	rejectGet     bool
	gets          atomic.Int64
	sets          atomic.Int64
	providerCalls atomic.Int64
}

func (c *delegationTestCacher) DelegationCache() *Cache {
	c.providerCalls.Add(1)
	if c.provide {
		return c.Cache
	}
	return nil
}

func (c *delegationTestCacher) DnsGet(name string, qtype uint16) *dns.Msg {
	c.gets.Add(1)
	if c.rejectGet {
		return nil
	}
	return c.Cache.DnsGet(name, qtype)
}

func (c *delegationTestCacher) DnsSet(msg *dns.Msg) {
	c.sets.Add(1)
	c.Cache.DnsSet(msg)
}

func TestDelegationCacheProviderLookup(t *testing.T) {
	for _, tc := range []struct {
		name          string
		provide       bool
		readOnly      bool
		stale         bool
		reject        bool
		rejectGet     bool
		wantGets      int64
		wantProviders int64
		wantShared    bool
		wantMissing   bool
	}{
		{name: "borrow", provide: true, readOnly: true, wantProviders: 1, wantShared: true},
		{name: "final", provide: true, wantGets: 1},
		{name: "decline", readOnly: true, wantGets: 1, wantProviders: 1},
		{name: "decline filtered", readOnly: true, rejectGet: true, wantGets: 1, wantProviders: 1, wantMissing: true},
		{name: "stale", provide: true, readOnly: true, stale: true, wantProviders: 1, wantMissing: true},
		{name: "reject", provide: true, readOnly: true, reject: true, wantProviders: 1, wantMissing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewCache()
			cache.MinTTL = 0
			ttl := "300"
			if tc.stale {
				ttl = "0"
			}
			cache.DnsSet(newResponseMsg("example.com.", dns.TypeNS, dns.RcodeSuccess, nil,
				[]dns.RR{mustNewTestRR(t, "example.com. "+ttl+" IN NS ns.example.com.")}, nil))
			stored := mustCacheValue(t, cache, "example.com.", dns.TypeNS).Msg
			wrapped := &delegationTestCacher{Cache: cache, provide: tc.provide, rejectGet: tc.rejectGet}
			q := &query{Recursive: NewWithOptions(nil, wrapped, []netip.Addr{}, []netip.Addr{}, nil), cache: wrapped}
			var allow func(*dns.Msg) bool
			if tc.reject {
				allow = func(*dns.Msg) bool { return false }
			}
			got, err := q.exchangeWithCachePolicy(t.Context(), "example.com.", dns.TypeNS, netip.Addr{}, allow, tc.readOnly)
			if err != nil || (got == nil) != tc.wantMissing {
				t.Fatalf("lookup = %v, %v; want missing=%t", got, err, tc.wantMissing)
			}
			if got != nil {
				if !got.Zero || (got == stored) != tc.wantShared {
					t.Fatalf("cached marker=%t, shared=%t; want shared=%t", got.Zero, got == stored, tc.wantShared)
				}
				if tc.wantShared && got.Ns[0].Header().Ttl != 300 {
					t.Fatalf("borrowed TTL = %d, want original 300", got.Ns[0].Header().Ttl)
				}
				if !tc.wantShared && got.Ns[0].Header().Ttl >= 300 {
					t.Fatalf("public TTL = %d, want remaining lifetime", got.Ns[0].Header().Ttl)
				}
			}
			if wrapped.gets.Load() != tc.wantGets || wrapped.providerCalls.Load() != tc.wantProviders {
				t.Fatalf("gets=%d providers=%d, want %d/%d", wrapped.gets.Load(), wrapped.providerCalls.Load(), tc.wantGets, tc.wantProviders)
			}
			if tc.stale && cache.Entries() != 0 {
				t.Fatal("expired entry was retained")
			}
		})
	}
}

func TestDelegationCacheProviderNegativeTTL(t *testing.T) {
	for _, rcode := range []int{dns.RcodeNameError, dns.RcodeServerFailure} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			cache := NewCache()
			cache.NXTTL = 20
			cache.DnsSet(newResponseMsg("missing.", dns.TypeNS, rcode, nil,
				[]dns.RR{mustNewTestRR(t, "missing. 300 IN SOA ns.missing. hostmaster.missing. 1 3600 900 604800 300")}, nil))
			stored := mustCacheValue(t, cache, "missing.", dns.TypeNS).Msg
			wrapped := &delegationTestCacher{Cache: cache, provide: true}
			q := &query{Recursive: NewWithOptions(nil, wrapped, []netip.Addr{}, []netip.Addr{}, nil), cache: wrapped}
			got, err := q.exchangeWithCachePolicy(t.Context(), "missing.", dns.TypeNS, netip.Addr{}, nil, true)
			if err != nil || got == nil || got.Rcode != rcode || got == stored || !got.Zero {
				t.Fatalf("negative lookup = %v, %v", got, err)
			}
			if got.Ns[0].Header().Ttl >= 300 || stored.Ns[0].Header().Ttl != 300 {
				t.Fatalf("negative TTLs: returned=%d stored=%d", got.Ns[0].Header().Ttl, stored.Ns[0].Header().Ttl)
			}
			if rcode == dns.RcodeNameError && got.Ns[0].Header().Ttl > cache.NXTTL {
				t.Fatalf("NXDOMAIN TTL = %d, want at most %d", got.Ns[0].Header().Ttl, cache.NXTTL)
			}
		})
	}
}

type rejectingDelegationCacher struct{ *Cache }

func (c rejectingDelegationCacher) DnsGet(string, uint16) *dns.Msg { return nil }

func TestDelegationCacheProviderRequiresOptIn(t *testing.T) {
	cache := NewCache()
	cache.DnsSet(newResponseMsg("example.com.", dns.TypeNS, dns.RcodeSuccess, nil,
		[]dns.RR{mustNewTestRR(t, "example.com. 300 IN NS ns.example.com.")}, nil))
	wrapped := rejectingDelegationCacher{cache}
	if _, ok := any(wrapped).(DelegationCacheProvider); ok {
		t.Fatal("embedding Cache implicitly enabled delegation reads")
	}
	q := &query{Recursive: NewWithOptions(nil, wrapped, []netip.Addr{}, []netip.Addr{}, nil), cache: wrapped}
	got, err := q.exchangeWithCachePolicy(t.Context(), "example.com.", dns.TypeNS, netip.Addr{}, nil, true)
	if got != nil || err != nil {
		t.Fatalf("filtered lookup = %v, %v; want nil", got, err)
	}
	q.cache = (*Cache)(nil)
	if got, err = q.exchangeWithCachePolicy(t.Context(), "example.com.", dns.TypeNS, netip.Addr{}, nil, true); got != nil || err != nil {
		t.Fatalf("typed-nil cache lookup = %v, %v; want nil", got, err)
	}
}

func TestDelegationCacheProviderRetainsWrapperWrites(t *testing.T) {
	server := netip.MustParseAddr("192.0.2.53")
	answer := mustNewTestRR(t, "example.com. 300 IN A 203.0.113.7")
	dialer := &scriptedDNSServerDialer{handlers: map[string]func(*dns.Msg) *dns.Msg{
		"192.0.2.53:53": func(req *dns.Msg) *dns.Msg {
			msg := new(dns.Msg)
			msg.SetReply(req)
			msg.Answer = []dns.RR{answer}
			return msg
		},
	}}
	wrapped := &delegationTestCacher{Cache: NewCache(), provide: true}
	rec := NewWithOptions(dialer, wrapped, []netip.Addr{server}, []netip.Addr{}, nil)
	rec.useUDP = false
	q := &query{Recursive: rec, cache: wrapped}
	got, err := q.exchangeWithCachePolicy(t.Context(), "example.com.", dns.TypeA, server, nil, true)
	if err != nil || got == nil || len(got.Answer) != 1 {
		t.Fatalf("network lookup = %v, %v", got, err)
	}
	if wrapped.sets.Load() != 1 || wrapped.gets.Load() != 0 || wrapped.providerCalls.Load() != 1 {
		t.Fatalf("sets/gets/providers = %d/%d/%d, want 1/0/1", wrapped.sets.Load(), wrapped.gets.Load(), wrapped.providerCalls.Load())
	}
	if wrapped.Cache.DnsGet("example.com.", dns.TypeA) == nil {
		t.Fatal("wrapper did not store the network answer")
	}
}

func cachedDelegationFixture(tb testing.TB) (cache *Cache) {
	tb.Helper()
	cache = NewCache()
	cache.MinTTL = 0
	for _, entry := range []struct {
		name string
		kind uint16
		aa   bool
		ans  []dns.RR
		ns   []dns.RR
		glue []dns.RR
	}{
		{"com.", dns.TypeNS, false, nil, []dns.RR{mustNewTestRR(tb, "com. 300 IN NS ns.com.")}, []dns.RR{mustNewTestRR(tb, "ns.com. 300 IN A 192.0.2.2")}},
		{"example.com.", dns.TypeNS, false, nil, []dns.RR{mustNewTestRR(tb, "example.com. 300 IN NS ns1.example.com.")}, []dns.RR{mustNewTestRR(tb, "ns1.example.com. 300 IN A 192.0.2.53")}},
		{"www.example.com.", dns.TypeNS, true, []dns.RR{mustNewTestRR(tb, "www.example.com. 300 IN NS ns1.www.example.com.")}, nil, []dns.RR{mustNewTestRR(tb, "ns1.www.example.com. 300 IN A 192.0.2.54")}},
		{"www.example.com.", dns.TypeA, true, []dns.RR{mustNewTestRR(tb, "www.example.com. 300 IN A 203.0.113.7")}, nil, nil},
	} {
		msg := newResponseMsg(entry.name, entry.kind, dns.RcodeSuccess, entry.ans, entry.ns, entry.glue)
		msg.Authoritative = entry.aa
		cache.DnsSet(msg)
	}
	return
}

func TestDelegationCacheProviderResolve(t *testing.T) {
	cache := cachedDelegationFixture(t)
	wrapped := &delegationTestCacher{Cache: cache, provide: true}
	rec := NewWithOptions(nil, wrapped, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []netip.Addr{}, nil)
	msg, _, err := rec.ResolveWithOptions(t.Context(), wrapped, nil, "www.example.com.", dns.TypeA)
	if err != nil || msg == nil || len(msg.Answer) != 1 || !msg.Zero {
		t.Fatalf("cached resolution = %v, %v", msg, err)
	}
	if got := msg.Answer[0].(*dns.A).A.String(); got != "203.0.113.7" {
		t.Fatalf("answer address = %q, want 203.0.113.7", got)
	}
	if msg.Answer[0].Header().Ttl >= 300 {
		t.Fatalf("final answer TTL = %d, want remaining lifetime", msg.Answer[0].Header().Ttl)
	}
	if wrapped.gets.Load() == 0 || wrapped.providerCalls.Load() == 0 {
		t.Fatalf("wrapper paths: gets=%d providers=%d", wrapped.gets.Load(), wrapped.providerCalls.Load())
	}
	if ttl := mustCacheValue(t, cache, "www.example.com.", dns.TypeA).Msg.Answer[0].Header().Ttl; ttl != 300 {
		t.Fatalf("stored answer TTL = %d, want 300", ttl)
	}
}

func TestDelegationCacheProviderConcurrentReplacement(t *testing.T) {
	cache := cachedDelegationFixture(t)
	wrapped := &delegationTestCacher{Cache: cache, provide: true}
	rec := NewWithOptions(nil, wrapped, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []netip.Addr{}, nil)
	rec.Deterministic = true
	stored := mustCacheValue(t, cache, "example.com.", dns.TypeNS).Msg
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				got, _, err := rec.ResolveWithOptions(t.Context(), wrapped, nil, "www.example.com.", dns.TypeA)
				if err != nil || got == nil || len(got.Answer) != 1 || !got.Zero {
					t.Errorf("cached resolution = %v, %v", got, err)
					return
				}
			}
		}()
	}
	for range 100 {
		msg := newResponseMsg("www.example.com.", dns.TypeA, dns.RcodeSuccess,
			[]dns.RR{mustNewTestRR(t, "www.example.com. 300 IN A 203.0.113.7")}, nil, nil)
		msg.Authoritative = true
		cache.DnsSet(msg)
	}
	workers.Wait()
	if stored.Ns[0].Header().Ttl != 300 {
		t.Fatalf("borrowed referral TTL changed: %d", stored.Ns[0].Header().Ttl)
	}
}
