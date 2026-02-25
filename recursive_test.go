package recursive

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var testSvc *Recursive

func init() {
	testSvc = NewWithOptions(nil, nil, nil, nil, nil)
	testSvc.Timeout = time.Second * 5
	testSvc.Deterministic = true
	testSvc.OrderRootsTimeout(context.Background(), time.Millisecond*100)
}

var networkOnce sync.Once
var networkCheckErr error

func requireNetwork(t *testing.T) {
	t.Helper()
	networkOnce.Do(func() {
		conn, err := net.DialTimeout("udp", net.JoinHostPort("1.1.1.1", "53"), time.Second)
		if err != nil {
			networkCheckErr = err
			return
		}
		_ = conn.Close()
	})
	if networkCheckErr != nil {
		t.Skipf("skipping network-dependent test: %v", networkCheckErr)
	}
}

func Test_A_console_aws_amazon_com(t *testing.T) {
	t.Parallel()
	requireNetwork(t)
	/*
		This domain tests that CNAME chains are followed.
	*/
	r := testSvc
	var buf bytes.Buffer
	defer func() {
		if t.Failed() {
			t.Log(buf.String())
		}
	}()
	qname := dns.Fqdn("console.aws.amazon.com")
	qtype := dns.TypeA
	msg, _, err := r.ResolveWithOptions(t.Context(), DefaultCache, &buf, qname, qtype)
	if err != nil {
		t.Fatal(err)
	}
	if x := msg.Rcode; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := msg.Question[0].Name; x != qname {
		t.Error(x)
	}
	if x := msg.Question[0].Qtype; x != qtype {
		t.Error(x)
	}
	travelled := make(map[string]struct{})
	var chainLength int
	var haveA bool
	var searching bool
	searching = true
	for searching {
		var foundCNAME bool
		for _, rr := range msg.Answer {
			var cname *dns.CNAME
			var ok bool
			if cname, ok = rr.(*dns.CNAME); ok {
				if strings.EqualFold(cname.Hdr.Name, qname) {
					var ownerKey string
					var haveLoop bool
					ownerKey = strings.ToLower(qname)
					if _, haveLoop = travelled[ownerKey]; haveLoop {
						t.Fatalf("cname loop detected at %s", qname)
					}
					travelled[ownerKey] = struct{}{}
					qname = strings.ToLower(dns.Fqdn(cname.Target))
					foundCNAME = true
				}
			}
		}
		if foundCNAME {
			chainLength++
			if chainLength > len(msg.Answer) {
				t.Fatalf("cname chain exceeded answers for %s", qname)
			}
		} else {
			for _, rr := range msg.Answer {
				var arecord *dns.A
				var ok bool
				if arecord, ok = rr.(*dns.A); ok {
					if strings.EqualFold(arecord.Hdr.Name, qname) {
						haveA = true
					}
				}
			}
			searching = false
		}
	}
	if chainLength < 1 {
		t.Fatalf("expected cname chain for %s", qname)
	}
	if !haveA {
		t.Fatalf("missing A record terminating chain at %s", qname)
	}
}

func Test_TXT_qnamemintest_internet_nl(t *testing.T) {
	t.Parallel()
	requireNetwork(t)
	/*
		This domain tests that QNAME minimization works.
	*/
	r := testSvc
	var buf bytes.Buffer
	defer func() {
		if t.Failed() {
			t.Log(buf.String())
		}
	}()
	qname := dns.Fqdn("qnamemintest.internet.nl")
	qtype := dns.TypeTXT
	msg, _, err := r.ResolveWithOptions(t.Context(), DefaultCache, &buf, qname, qtype)
	if err != nil {
		t.Fatal(err)
	}
	if x := msg.Rcode; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := msg.Question[0].Name; x != qname {
		t.Error(x)
	}
	if x := msg.Question[0].Qtype; x != qtype {
		t.Error(x)
	}
	if x := len(msg.Answer); x < 1 {
		t.Fatal(x)
	}
	found := false
	for _, rr := range msg.Answer {
		if rr, ok := rr.(*dns.TXT); ok {
			for _, txt := range rr.Txt {
				found = found || strings.HasPrefix(txt, "HOORAY")
			}
		}
	}
	if !found {
		t.Error("expected a TXT record starting with HOORAY")
		t.Log(msg.Answer)
	}
}

func Test_NS_bankgirot_nu(t *testing.T) {
	t.Parallel()
	requireNetwork(t)
	/*
	   This domain has delegation servers that do not respond.
	   We expect the final queries to time out, but since we
	   have a NS answer (the delegation servers) for the query
	   we want a response with those:

	   bankgirot.nu.	86400	IN	NS	sem1.eun.net.
	   bankgirot.nu.	86400	IN	NS	sem2.eun.net.
	   bankgirot.nu.	86400	IN	NS	sem3.eun.net.
	*/

	r := testSvc
	var buf bytes.Buffer
	defer func() {
		if t.Failed() {
			t.Log(buf.String())
		}
	}()
	qname := dns.Fqdn("bankgirot.nu")
	qtype := dns.TypeNS
	msg, _, err := r.ResolveWithOptions(t.Context(), DefaultCache, &buf, qname, qtype)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Rcode == dns.RcodeNameError {
		t.Skip(qname, "no longer exists")
	}
	if x := msg.Rcode; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := msg.Question[0].Name; x != qname {
		t.Error(x)
	}
	if x := msg.Question[0].Qtype; x != qtype {
		t.Error(x)
	}
	if x := len(msg.Answer); x < 1 {
		t.Log(len(msg.Ns))
		t.Fatal(x)
	}
	expect := map[string]struct{}{
		"sem1.eun.net.": {},
		"sem2.eun.net.": {},
		"sem3.eun.net.": {},
	}
	for _, rr := range msg.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			t.Fatalf("unexpected rr type %T", rr)
		}
		if !strings.EqualFold(ns.Hdr.Name, qname) {
			t.Fatalf("unexpected owner %s", ns.Hdr.Name)
		}
		k := strings.ToLower(dns.Fqdn(ns.Ns))
		delete(expect, k)
	}
	if len(expect) > 0 {
		t.Fatalf("missing expected ns records: %v", expect)
	}
}

func Test_A_nonexistant_example_com(t *testing.T) {
	t.Parallel()
	requireNetwork(t)
	r := testSvc
	var buf bytes.Buffer
	defer func() {
		if t.Failed() {
			t.Log(buf.String())
		}
	}()
	qname := dns.Fqdn("nonexistant.example.com")
	qtype := dns.TypeA
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
	defer cancel()
	msg, _, err := r.ResolveWithOptions(ctx, DefaultCache, &buf, qname, qtype)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Rcode != dns.RcodeNameError {
		t.Error("expected NXDOMAIN, not", msg.Rcode)
	}
	if x := msg.Question[0].Name; x != qname {
		t.Error(x)
	}
	if x := msg.Question[0].Qtype; x != qtype {
		t.Error(x)
	}
}

func newResponseMsg(qname string, qtype uint16, rcode int, answer, authority, extra []dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Rcode = rcode
	if len(answer) > 0 {
		msg.Answer = append(msg.Answer, answer...)
	}
	if len(authority) > 0 {
		msg.Ns = append(msg.Ns, authority...)
	}
	if len(extra) > 0 {
		msg.Extra = append(msg.Extra, extra...)
	}
	return msg
}

func TestResolverCacheStoreAndGet(t *testing.T) {
	t.Parallel()
	cacher := NewCache()
	qname := dns.Fqdn("cache.example.com")
	qtype := dns.TypeA
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: qtype,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(192, 0, 2, 42),
	}
	msg := newResponseMsg(qname, qtype, dns.RcodeSuccess, []dns.RR{answer}, nil, nil)
	cacher.DnsSet(msg)
	cached := cacher.DnsGet(qname, qtype)
	if cached == nil {
		t.Fatalf("expected cached response for %s %s", qname, dns.Type(qtype))
	}
	if !cached.Zero {
		t.Fatal("cached response must have Zero bit set")
	}
	cachedAgain := cacher.DnsGet(qname, qtype)
	if cachedAgain == nil {
		t.Fatal("expected cached response on second lookup")
	}
	if !dnsMsgsEqual(cachedAgain, cached) {
		t.Fatalf("expected equivalent cached responses got=%v want=%v", cachedAgain.Question, cached.Question)
	}
	if cachedAgain.Question[0].Name != qname {
		t.Fatalf("cached question changed got=%s want=%s", cachedAgain.Question[0].Name, qname)
	}
}

func TestResolverCacheSkipsZeroResponses(t *testing.T) {
	t.Parallel()
	cacher := NewCache()
	qname := dns.Fqdn("skip-cache.example.com")
	qtype := dns.TypeA
	msg := newResponseMsg(qname, qtype, dns.RcodeSuccess, nil, nil, nil)
	msg.Zero = true
	if cached := cacher.DnsGet(qname, qtype); cached != nil {
		t.Fatalf("expected no cache entry, got %v", cached)
	}
}

func TestResolverResolveUsesProvidedCache(t *testing.T) {
	t.Parallel()
	r := New(nil)
	qname := dns.Fqdn("cached.example.com")
	qtype := dns.TypeA
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: qtype,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(192, 0, 2, 25),
	}
	cachedMsg := newResponseMsg(qname, qtype, dns.RcodeSuccess, []dns.RR{answer}, nil, nil)
	cachedMsg.Zero = true
	override := &recordingCacher{msg: cachedMsg}
	originalQuestion := override.msg.Question[0].Name
	var buf bytes.Buffer
	msg, _, err := r.ResolveWithOptions(t.Context(), override, &buf, qname, qtype)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("expected message from cache override")
	}
	if !msg.Zero {
		t.Fatal("expected cached result to keep zero bit set")
	}
	if msg != override.msg {
		t.Fatalf("resolver returned unexpected message pointer got=%p want=%p", msg, override.msg)
	}
	if x := override.getCount; x < 1 {
		t.Fatalf("override cache get count got=%d want > 0", x)
	}
	if x := override.setCount; x != 0 {
		t.Fatalf("override cache set count got=%d want=0", x)
	}
	if override.msg.Question[0].Name != originalQuestion {
		t.Fatalf("override cache msg mutated got=%s want=%s", override.msg.Question[0].Name, originalQuestion)
	}
}

func TestCloneIfCached(t *testing.T) {
	t.Parallel()
	original := newResponseMsg(dns.Fqdn("clone-cache.example."), dns.TypeA, dns.RcodeSuccess, nil, nil, nil)
	original.Zero = true
	cloned := cloneIfCached(original)
	if cloned == nil {
		t.Fatal("expected clone for cached message")
	}
	if cloned == original {
		t.Fatal("cloneIfCached should return a new message when Zero is set")
	}
	if cloned.Zero {
		t.Fatal("clone should clear Zero bit for new message")
	}
	cloneQuestion := "mutated.clone-cache.example."
	cloned.Question[0].Name = cloneQuestion
	if original.Question[0].Name == cloneQuestion {
		t.Fatal("cloneIfCached mutated original message")
	}
	fresh := newResponseMsg(dns.Fqdn("fresh.example."), dns.TypeA, dns.RcodeSuccess, nil, nil, nil)
	freshClone := cloneIfCached(fresh)
	if freshClone != fresh {
		t.Fatal("cloneIfCached should return original when Zero is not set")
	}
}

func TestPrependRecordsKeepsFinalAuthorityForCNAME(t *testing.T) {
	t.Parallel()

	cnameOwner := dns.Fqdn("alias.example.")
	targetName := dns.Fqdn("target.example.")
	qtype := dns.TypeA
	finalAnswer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   targetName,
			Rrtype: qtype,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(192, 0, 2, 100),
	}

	finalAuthority := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   targetName,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: dns.Fqdn("ns.target.example."),
	}

	finalMsg := newResponseMsg(targetName, qtype, dns.RcodeSuccess, []dns.RR{finalAnswer}, []dns.RR{finalAuthority}, nil)
	cname := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   cnameOwner,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: targetName,
	}

	initialAuthority := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   cnameOwner,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: dns.Fqdn("ns.alias.example."),
	}

	initialMsg := newResponseMsg(cnameOwner, qtype, dns.RcodeSuccess, []dns.RR{cname}, []dns.RR{initialAuthority}, nil)

	prependRecords(finalMsg, initialMsg, cnameOwner, cnameChainRecords)

	nsCount := len(finalMsg.Ns)
	if nsCount != 1 {
		t.Fatalf("expected final authority count of 1 got=%d", nsCount)
	}

	var ns *dns.NS
	var ok bool
	if ns, ok = finalMsg.Ns[0].(*dns.NS); !ok {
		t.Fatalf("expected authority rr type *dns.NS got=%T", finalMsg.Ns[0])
	}

	if !strings.EqualFold(ns.Ns, dns.Fqdn("ns.target.example.")) {
		t.Fatalf("unexpected authority ns got=%s want=%s", ns.Ns, dns.Fqdn("ns.target.example."))
	}
}

type recordingCacher struct {
	msg      *dns.Msg
	getCount int
	setCount int
}

func (c *recordingCacher) DnsSet(msg *dns.Msg) {
	c.setCount++
	c.msg = msg
}

func (c *recordingCacher) DnsGet(string, uint16) *dns.Msg {
	c.getCount++
	return c.msg
}
func TestServiceDnsResolveWithoutRoots(t *testing.T) {
	t.Parallel()

	DefaultCache.Clear()
	svc := &Recursive{}

	msg, srv, err := svc.DnsResolve(context.Background(), dns.Fqdn("unit-test-no-roots"), dns.TypeA)
	if !errors.Is(err, ErrNoResponse) {
		t.Fatalf("DnsResolve error = %v, want ErrNoResponse", err)
	}
	if msg != nil {
		t.Fatalf("DnsResolve returned unexpected message: %v", msg)
	}
	if srv.IsValid() {
		t.Fatalf("DnsResolve returned unexpected server %v", srv)
	}
}

func TestResolveWithOptionsCanonicalizesInputQName(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	root := netip.MustParseAddr("192.0.2.1")
	rawQname := "Host.Missing.Example.COM."
	qname := dns.CanonicalName(rawQname)

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
	missing.Rcode = dns.RcodeSuccess
	missing.Authoritative = true
	cache.DnsSet(missing)

	full := new(dns.Msg)
	full.SetQuestion(qname, dns.TypeNS)
	full.Rcode = dns.RcodeNameError
	cache.DnsSet(full)

	rec := NewWithOptions(nil, cache, []netip.Addr{root}, nil, nil)

	resp, _, err := rec.ResolveWithOptions(context.Background(), cache, nil, rawQname, dns.TypeA)
	if err != nil {
		t.Fatalf("ResolveWithOptions returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("ResolveWithOptions returned nil response")
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

func TestGetRoots(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")
	r := &Recursive{rootServers: []netip.Addr{ipv4, ipv6}}
	roots4, roots6 := r.GetRoots()
	if len(roots4) != 1 || roots4[0] != ipv4 {
		t.Fatalf("roots4 = %v; want [%v]", roots4, ipv4)
	}
	if len(roots6) != 1 || roots6[0] != ipv6 {
		t.Fatalf("roots6 = %v; want [%v]", roots6, ipv6)
	}
}
