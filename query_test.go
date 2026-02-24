package recursive

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
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

func TestDnameSynthesizeRequiresLabelBoundary(t *testing.T) {
	t.Parallel()

	rr, err := dns.NewRR("example.com. 3600 IN DNAME target.example.net.")
	if err != nil {
		t.Fatalf("failed to build DNAME RR: %v", err)
	}

	msg := &dns.Msg{Answer: []dns.RR{rr}}
	got := dnameSynthesize(msg, dns.Fqdn("notexample.com"))
	if got != "" {
		t.Fatalf("dnameSynthesize() = %q, want empty string", got)
	}
}

func TestDnameRecordsRequiresLabelBoundary(t *testing.T) {
	t.Parallel()

	rr, err := dns.NewRR("example.com. 3600 IN DNAME target.example.net.")
	if err != nil {
		t.Fatalf("failed to build DNAME RR: %v", err)
	}

	records := dnameRecords([]dns.RR{rr}, dns.Fqdn("notexample.com"))
	if len(records) != 0 {
		t.Fatalf("dnameRecords returned %d entries, want 0", len(records))
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

func TestQueryForDelegationDoesNotFallbackOnEmptyMinimizedSuccess(t *testing.T) {
	t.Parallel()

	parent := netip.MustParseAddr("192.0.2.1")
	cache := NewCache()

	minimizedEmpty := new(dns.Msg)
	minimizedEmpty.SetQuestion("example.com.", dns.TypeNS)
	minimizedEmpty.Rcode = dns.RcodeSuccess
	cache.DnsSet(minimizedEmpty)

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
	if len(addrs) != 0 {
		t.Fatalf("unexpected delegation addresses: %#v", addrs)
	}
	if resp.Question[0].Name != "example.com." {
		t.Fatalf("unexpected question name: %q", resp.Question[0].Name)
	}
}

func TestQueryForDelegationFallbacksOnAuthoritativeEmptyMinimizedSuccess(t *testing.T) {
	t.Parallel()

	zone := dns.Fqdn("example.com")
	fullQname := dns.Fqdn("www.example.com")
	parent := netip.MustParseAddr("192.0.2.1")
	referralAddr := netip.MustParseAddr("192.0.2.53")
	parentAddr := netip.AddrPortFrom(parent, 53).String()

	var queryCount int
	var mu sync.Mutex
	dialer := &scriptedDNSServerDialer{
		handlers: map[string]func(req *dns.Msg) *dns.Msg{
			parentAddr: func(req *dns.Msg) *dns.Msg {
				mu.Lock()
				queryCount++
				mu.Unlock()

				resp := new(dns.Msg)
				resp.SetReply(req)

				if req.Question[0].Name == zone {
					resp.Rcode = dns.RcodeSuccess
					resp.Authoritative = true
					return resp
				}
				if req.Question[0].Name == fullQname {
					resp.Rcode = dns.RcodeSuccess
					ns := &dns.NS{
						Hdr: dns.RR_Header{
							Name:   zone,
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns: dns.Fqdn("ns1.example.net"),
					}
					glue := &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn("ns1.example.net"),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 53),
					}
					resp.Ns = []dns.RR{ns}
					resp.Extra = []dns.RR{glue}
					return resp
				}

				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
		},
	}

	rec := NewWithOptions(dialer, nil, []netip.Addr{parent}, nil, nil)
	rec.useUDP = false
	q := &query{
		Recursive: rec,
		glue:      make(map[string][]netip.Addr),
	}

	addrs, resp, _, err := q.queryForDelegation(context.Background(), zone, []netip.Addr{parent}, fullQname)
	if err != nil {
		t.Fatalf("queryForDelegation returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("queryForDelegation returned nil response")
	}
	mu.Lock()
	qc := queryCount
	mu.Unlock()
	if qc < 2 {
		t.Fatalf("expected at least 2 queries (minimized + full), got %d", qc)
	}
	if len(addrs) != 1 || addrs[0] != referralAddr {
		t.Fatalf("expected fallback referral %v, got %v", referralAddr, addrs)
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

func TestResolveNXDOMAINUsesOriginalQuestionName(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	root := netip.MustParseAddr("192.0.2.1")
	qname := dns.Fqdn("host.missing.example.com")

	com := new(dns.Msg)
	com.SetQuestion(dns.Fqdn("com"), dns.TypeNS)
	com.Rcode = dns.RcodeSuccess
	com.Authoritative = true
	cache.DnsSet(com)

	example := new(dns.Msg)
	example.SetQuestion(dns.Fqdn("example.com"), dns.TypeNS)
	example.Rcode = dns.RcodeSuccess
	example.Authoritative = true
	cache.DnsSet(example)

	missing := new(dns.Msg)
	missing.SetQuestion(dns.Fqdn("missing.example.com"), dns.TypeNS)
	missing.Rcode = dns.RcodeNameError
	cache.DnsSet(missing)

	full := new(dns.Msg)
	full.SetQuestion(qname, dns.TypeNS)
	full.Rcode = dns.RcodeNameError
	cache.DnsSet(full)

	rec := NewWithOptions(nil, cache, []netip.Addr{root}, nil, nil)
	q := &query{Recursive: rec, cache: cache, glue: make(map[string][]netip.Addr)}

	resp, _, err := q.resolve(context.Background(), qname, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("resolve returned nil response")
	}
	if x := resp.Rcode; x != dns.RcodeNameError {
		t.Fatalf("unexpected rcode %s", dns.RcodeToString[x])
	}
	if x := resp.Question[0].Name; x != qname {
		t.Fatalf("unexpected question name got=%q want=%q", x, qname)
	}
	if x := resp.Question[0].Qtype; x != dns.TypeA {
		t.Fatalf("unexpected question qtype got=%s want=%s", dns.Type(x), dns.Type(dns.TypeA))
	}
}

func TestQueryForDelegationRetriesOtherParentsAfterFallbackFailure(t *testing.T) {
	t.Parallel()

	zone := dns.Fqdn("example.com")
	fullQname := dns.Fqdn("www.example.com")
	parent1 := netip.MustParseAddr("192.0.2.1")
	parent2 := netip.MustParseAddr("192.0.2.2")
	referralAddr := netip.MustParseAddr("192.0.2.53")

	parent1Addr := netip.AddrPortFrom(parent1, 53).String()
	parent2Addr := netip.AddrPortFrom(parent2, 53).String()

	dialer := &scriptedDNSServerDialer{
		handlers: map[string]func(req *dns.Msg) *dns.Msg{
			parent1Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
			parent2Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeSuccess
				ns := &dns.NS{
					Hdr: dns.RR_Header{
						Name:   zone,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Ns: dns.Fqdn("ns1.example.net"),
				}
				glue := &dns.A{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn("ns1.example.net"),
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.IPv4(192, 0, 2, 53),
				}
				resp.Ns = []dns.RR{ns}
				resp.Extra = []dns.RR{glue}
				return resp
			},
		},
	}

	rec := NewWithOptions(dialer, nil, []netip.Addr{parent1, parent2}, nil, nil)
	rec.useUDP = false
	q := &query{
		Recursive: rec,
		glue:      make(map[string][]netip.Addr),
	}

	addrs, resp, _, err := q.queryForDelegation(context.Background(), zone, []netip.Addr{parent1, parent2}, fullQname)
	if err != nil {
		t.Fatalf("queryForDelegation returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("queryForDelegation returned nil response")
	}
	if len(addrs) != 1 || addrs[0] != referralAddr {
		t.Fatalf("queryForDelegation returned unexpected addrs: %v", addrs)
	}
	if calls := dialer.callsTo(parent2Addr); calls == 0 {
		t.Fatalf("expected parent2 to be queried after fallback failure")
	}
}

// TestQueryForDelegationRetriesFullQnameOnMinimizedNXDOMAIN verifies that when
// a parent server returns NXDOMAIN for a QNAME-minimized zone query, the resolver
// retries with the full qname before giving up. Per RFC 9156, some servers
// incorrectly return NXDOMAIN for minimized NS queries even though the actual
// domain exists.
func TestQueryForDelegationRetriesFullQnameOnMinimizedNXDOMAIN(t *testing.T) {
	t.Parallel()

	zone := dns.Fqdn("example.com")
	fullQname := dns.Fqdn("www.example.com")
	parent := netip.MustParseAddr("192.0.2.1")
	referralAddr := netip.MustParseAddr("192.0.2.53")
	parentAddr := netip.AddrPortFrom(parent, 53).String()

	var queryCount int
	var mu sync.Mutex
	dialer := &scriptedDNSServerDialer{
		handlers: map[string]func(req *dns.Msg) *dns.Msg{
			parentAddr: func(req *dns.Msg) *dns.Msg {
				mu.Lock()
				queryCount++
				mu.Unlock()

				resp := new(dns.Msg)
				resp.SetReply(req)

				// Minimized query (NS example.com.) returns NXDOMAIN
				if req.Question[0].Name == zone {
					resp.Rcode = dns.RcodeNameError
					return resp
				}

				// Full query (NS www.example.com.) returns a referral
				if req.Question[0].Name == fullQname {
					resp.Rcode = dns.RcodeSuccess
					ns := &dns.NS{
						Hdr: dns.RR_Header{
							Name:   zone,
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns: dns.Fqdn("ns1.example.net"),
					}
					glue := &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn("ns1.example.net"),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 53),
					}
					resp.Ns = []dns.RR{ns}
					resp.Extra = []dns.RR{glue}
					return resp
				}

				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
		},
	}

	rec := NewWithOptions(dialer, nil, []netip.Addr{parent}, nil, nil)
	rec.useUDP = false
	q := &query{
		Recursive: rec,
		glue:      make(map[string][]netip.Addr),
	}

	addrs, resp, _, err := q.queryForDelegation(context.Background(), zone, []netip.Addr{parent}, fullQname)
	if err != nil {
		t.Fatalf("queryForDelegation returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("queryForDelegation returned nil response")
	}
	mu.Lock()
	qc := queryCount
	mu.Unlock()
	if qc < 2 {
		t.Fatalf("expected at least 2 queries (minimized + full), got %d", qc)
	}
	if len(addrs) != 1 || addrs[0] != referralAddr {
		t.Fatalf("expected delegation to %v, got %v", referralAddr, addrs)
	}
}

// TestQueryForDelegationIgnoresNonAuthoritativeNXDOMAINOnFallback verifies that
// a non-authoritative NXDOMAIN received after the resolver has already fallen
// back to the full qname does not terminate resolution early; the resolver must
// continue trying other parent servers.
func TestQueryForDelegationIgnoresNonAuthoritativeNXDOMAINOnFallback(t *testing.T) {
	t.Parallel()

	zone := dns.Fqdn("example.com")
	fullQname := dns.Fqdn("www.example.com")
	parent1 := netip.MustParseAddr("192.0.2.1")
	parent2 := netip.MustParseAddr("192.0.2.2")
	referralAddr := netip.MustParseAddr("192.0.2.53")
	parent1Addr := netip.AddrPortFrom(parent1, 53).String()
	parent2Addr := netip.AddrPortFrom(parent2, 53).String()

	dialer := &scriptedDNSServerDialer{
		handlers: map[string]func(req *dns.Msg) *dns.Msg{
			parent1Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)

				if req.Question[0].Name == zone {
					resp.Rcode = dns.RcodeRefused
					return resp
				}
				if req.Question[0].Name == fullQname {
					resp.Rcode = dns.RcodeNameError
					resp.Authoritative = false
					return resp
				}

				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
			parent2Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)

				if req.Question[0].Name == fullQname {
					resp.Rcode = dns.RcodeSuccess
					ns := &dns.NS{
						Hdr: dns.RR_Header{
							Name:   zone,
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns: dns.Fqdn("ns1.example.net"),
					}
					glue := &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn("ns1.example.net"),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 53),
					}
					resp.Ns = []dns.RR{ns}
					resp.Extra = []dns.RR{glue}
					return resp
				}

				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
		},
	}

	rec := NewWithOptions(dialer, nil, []netip.Addr{parent1, parent2}, nil, nil)
	rec.useUDP = false
	q := &query{
		Recursive: rec,
		glue:      make(map[string][]netip.Addr),
	}

	addrs, resp, _, err := q.queryForDelegation(context.Background(), zone, []netip.Addr{parent1, parent2}, fullQname)
	if err != nil {
		t.Fatalf("queryForDelegation returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("queryForDelegation returned nil response")
	}
	if len(addrs) != 1 || addrs[0] != referralAddr {
		t.Fatalf("expected fallback referral %v, got %v", referralAddr, addrs)
	}
	if calls := dialer.callsTo(parent2Addr); calls == 0 {
		t.Fatalf("expected parent2 to be queried after non-authoritative NXDOMAIN")
	}
}

// TestQueryForDelegationDoesNotPoisonCacheWithMinimizedNXDOMAIN verifies that
// an NXDOMAIN response seen during a minimized NS query does not poison future
// exact-zone NS lookups via cache reuse.
func TestQueryForDelegationDoesNotPoisonCacheWithMinimizedNXDOMAIN(t *testing.T) {
	t.Parallel()

	zone := dns.Fqdn("example.com")
	fullQname := dns.Fqdn("www.example.com")
	parent := netip.MustParseAddr("192.0.2.1")
	referralAddr := netip.MustParseAddr("192.0.2.53")
	parentAddr := netip.AddrPortFrom(parent, 53).String()

	var minimizedQueries int
	var mu sync.Mutex
	dialer := &scriptedDNSServerDialer{
		handlers: map[string]func(req *dns.Msg) *dns.Msg{
			parentAddr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)

				if req.Question[0].Name == zone {
					mu.Lock()
					minimizedQueries++
					seen := minimizedQueries
					mu.Unlock()

					// First minimized query incorrectly returns NXDOMAIN.
					if seen == 1 {
						resp.Rcode = dns.RcodeNameError
						return resp
					}

					// Subsequent exact-zone lookups are valid referrals.
					resp.Rcode = dns.RcodeSuccess
					ns := &dns.NS{
						Hdr: dns.RR_Header{
							Name:   zone,
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns: dns.Fqdn("ns1.example.net"),
					}
					glue := &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn("ns1.example.net"),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 53),
					}
					resp.Ns = []dns.RR{ns}
					resp.Extra = []dns.RR{glue}
					return resp
				}

				if req.Question[0].Name == fullQname {
					resp.Rcode = dns.RcodeSuccess
					ns := &dns.NS{
						Hdr: dns.RR_Header{
							Name:   zone,
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns: dns.Fqdn("ns1.example.net"),
					}
					glue := &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn("ns1.example.net"),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 53),
					}
					resp.Ns = []dns.RR{ns}
					resp.Extra = []dns.RR{glue}
					return resp
				}

				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
		},
	}

	cache := NewCache()
	rec := NewWithOptions(dialer, cache, []netip.Addr{parent}, nil, nil)
	rec.useUDP = false
	q := &query{
		Recursive: rec,
		cache:     cache,
		glue:      make(map[string][]netip.Addr),
	}

	// First: minimized lookup path should fallback to full qname and succeed.
	addrs, resp, _, err := q.queryForDelegation(context.Background(), zone, []netip.Addr{parent}, fullQname)
	if err != nil {
		t.Fatalf("first queryForDelegation returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("first queryForDelegation returned nil response")
	}
	if len(addrs) != 1 || addrs[0] != referralAddr {
		t.Fatalf("first query returned unexpected addrs: %v", addrs)
	}

	// Second: exact-zone lookup should not be served by cached minimized NXDOMAIN.
	addrs, resp, _, err = q.queryForDelegation(context.Background(), zone, []netip.Addr{parent}, zone)
	if err != nil {
		t.Fatalf("second queryForDelegation returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("second queryForDelegation returned nil response")
	}
	if len(addrs) != 1 || addrs[0] != referralAddr {
		t.Fatalf("second query returned unexpected addrs: %v", addrs)
	}
	if calls := dialer.callsToNetwork("tcp4", parentAddr); calls < 3 {
		t.Fatalf("expected second query to hit network (not poisoned cache), total tcp calls=%d", calls)
	}
}

// TestPrependRecordsDoesNotDuplicateOPT verifies that prependRecords does not
// create messages with duplicate OPT pseudo-records when combining Extra
// sections from intermediate and final responses (RFC 6891 violation).
func TestPrependRecordsDoesNotDuplicateOPT(t *testing.T) {
	t.Parallel()

	cnameOwner := dns.Fqdn("alias.example.")
	targetName := dns.Fqdn("target.example.")

	finalAnswer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   targetName,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(192, 0, 2, 100),
	}
	finalOPT := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	finalOPT.SetUDPSize(1232)
	finalMsg := newResponseMsg(targetName, dns.TypeA, dns.RcodeSuccess, []dns.RR{finalAnswer}, nil, []dns.RR{finalOPT})

	cname := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   cnameOwner,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: targetName,
	}
	initialOPT := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	initialOPT.SetUDPSize(4096)
	initialMsg := newResponseMsg(cnameOwner, dns.TypeA, dns.RcodeSuccess, []dns.RR{cname}, nil, []dns.RR{initialOPT})

	prependRecords(finalMsg, initialMsg, cnameOwner, cnameChainRecords)

	var optCount int
	for _, rr := range finalMsg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			optCount++
		}
	}
	if optCount > 1 {
		t.Fatalf("prependRecords created %d OPT records, RFC 6891 allows at most 1", optCount)
	}
	if optCount < 1 {
		t.Fatalf("prependRecords removed all OPT records, expected 1")
	}
}

func TestQueryFinalDoesNotReuseCachedServerFailureAcrossServers(t *testing.T) {
	t.Parallel()

	qname := dns.Fqdn("www.example.com")
	qtype := dns.TypeA

	srv1 := netip.MustParseAddr("192.0.2.1")
	srv2 := netip.MustParseAddr("192.0.2.2")
	srv1Addr := netip.AddrPortFrom(srv1, 53).String()
	srv2Addr := netip.AddrPortFrom(srv2, 53).String()

	dialer := &scriptedDNSServerDialer{
		handlers: map[string]func(req *dns.Msg) *dns.Msg{
			srv1Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
			srv2Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 123),
					},
				}
				return resp
			},
		},
	}

	cache := NewCache()
	rec := NewWithOptions(dialer, cache, []netip.Addr{srv1, srv2}, nil, nil)
	rec.useUDP = false
	q := &query{
		Recursive: rec,
		cache:     cache,
		glue:      make(map[string][]netip.Addr),
	}

	resp, gotSrv, err := q.queryFinal(context.Background(), qname, qtype, []netip.Addr{srv1, srv2})
	if err != nil {
		t.Fatalf("queryFinal returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("queryFinal returned nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success from second server, got %s", dns.RcodeToString[resp.Rcode])
	}
	if gotSrv != srv2 {
		t.Fatalf("expected answer from second server %v, got %v", srv2, gotSrv)
	}
}

func TestQueryFinalSkipsNonAuthoritativeReferralLikeSuccess(t *testing.T) {
	t.Parallel()

	qname := dns.Fqdn("www.example.com")
	qtype := dns.TypeA

	srv1 := netip.MustParseAddr("192.0.2.1")
	srv2 := netip.MustParseAddr("192.0.2.2")
	srv1Addr := netip.AddrPortFrom(srv1, 53).String()
	srv2Addr := netip.AddrPortFrom(srv2, 53).String()

	dialer := &scriptedDNSServerDialer{
		handlers: map[string]func(req *dns.Msg) *dns.Msg{
			srv1Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeSuccess
				resp.Ns = []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn("example.com"),
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns: dns.Fqdn("ns1.example.com"),
					},
				}
				resp.Extra = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn("ns1.example.com"),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 53),
					},
				}
				return resp
			},
			srv2Addr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 123),
					},
				}
				resp.Authoritative = true
				return resp
			},
		},
	}

	rec := NewWithOptions(dialer, nil, []netip.Addr{srv1, srv2}, nil, nil)
	rec.useUDP = false
	q := &query{
		Recursive: rec,
		glue:      make(map[string][]netip.Addr),
	}

	resp, gotSrv, err := q.queryFinal(context.Background(), qname, qtype, []netip.Addr{srv1, srv2})
	if err != nil {
		t.Fatalf("queryFinal returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("queryFinal returned nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success from second server, got %s", dns.RcodeToString[resp.Rcode])
	}
	if gotSrv != srv2 {
		t.Fatalf("expected answer from second server %v, got %v", srv2, gotSrv)
	}
	if calls := dialer.callsTo(srv2Addr); calls == 0 {
		t.Fatalf("expected second server to be queried after referral-like response")
	}
}

func TestExchangeRetriesTCPOnTruncatedNXDOMAIN(t *testing.T) {
	t.Parallel()

	qname := dns.Fqdn("www.example.com")
	qtype := dns.TypeA
	srv := netip.MustParseAddr("192.0.2.1")
	srvAddr := netip.AddrPortFrom(srv, 53).String()

	dialer := &scriptedDNSServerDialer{
		networkHandlers: map[string]func(req *dns.Msg) *dns.Msg{
			"udp4|" + srvAddr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeNameError
				resp.Truncated = true
				return resp
			},
			"tcp4|" + srvAddr: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IPv4(192, 0, 2, 123),
					},
				}
				return resp
			},
		},
	}

	rec := NewWithOptions(dialer, nil, []netip.Addr{srv}, nil, nil)
	q := &query{
		Recursive: rec,
		glue:      make(map[string][]netip.Addr),
	}

	resp, err := q.exchange(context.Background(), qname, qtype, srv)
	if err != nil {
		t.Fatalf("exchange returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("exchange returned nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful TCP response, got %s", dns.RcodeToString[resp.Rcode])
	}
	if calls := dialer.callsToNetwork("tcp4", srvAddr); calls < 1 {
		t.Fatalf("expected TCP retry after truncated UDP NXDOMAIN, got %d tcp calls", calls)
	}
}

type scriptedDNSServerDialer struct {
	mu              sync.Mutex
	handlers        map[string]func(req *dns.Msg) *dns.Msg
	networkHandlers map[string]func(req *dns.Msg) *dns.Msg
	calls           []string
	networkCalls    []string
}

func (d *scriptedDNSServerDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()

	d.mu.Lock()
	d.calls = append(d.calls, address)
	key := network + "|" + address
	d.networkCalls = append(d.networkCalls, key)
	handler := d.handlers[address]
	if nh := d.networkHandlers[key]; nh != nil {
		handler = nh
	}
	d.mu.Unlock()

	go func() {
		defer func() {
			_ = serverConn.Close()
		}()
		var lengthPrefix [2]byte
		if _, err := io.ReadFull(serverConn, lengthPrefix[:]); err == nil {
			msgLen := int(binary.BigEndian.Uint16(lengthPrefix[:]))
			requestPayload := make([]byte, msgLen)
			if _, err = io.ReadFull(serverConn, requestPayload); err == nil {
				var request dns.Msg
				if err = request.Unpack(requestPayload); err == nil {
					response := new(dns.Msg)
					response.SetReply(&request)
					response.Rcode = dns.RcodeServerFailure
					if handler != nil {
						response = handler(&request)
					}
					if payload, err := response.Pack(); err == nil {
						var responseWire bytes.Buffer
						_ = binary.Write(&responseWire, binary.BigEndian, uint16(len(payload)))
						_, _ = responseWire.Write(payload)
						_, _ = serverConn.Write(responseWire.Bytes())
					}
				}
			}
		}
	}()

	return clientConn, nil
}

func (d *scriptedDNSServerDialer) callsTo(address string) (n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, call := range d.calls {
		if call == address {
			n++
		}
	}
	return
}

func (d *scriptedDNSServerDialer) callsToNetwork(network, address string) (n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := network + "|" + address
	for _, call := range d.networkCalls {
		if call == key {
			n++
		}
	}
	return
}
