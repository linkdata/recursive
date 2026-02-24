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

type scriptedDNSServerDialer struct {
	mu       sync.Mutex
	handlers map[string]func(req *dns.Msg) *dns.Msg
	calls    []string
}

func (d *scriptedDNSServerDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()

	d.mu.Lock()
	d.calls = append(d.calls, address)
	handler := d.handlers[address]
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
