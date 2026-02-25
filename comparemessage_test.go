package recursive

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestCompareMessageEquivalentIgnoresTTLAndOrderAndOPT(t *testing.T) {
	t.Parallel()

	answerA := mustNewTestRR(t, "example.org. 300 IN A 192.0.2.10")
	answerAAAA := mustNewTestRR(t, "example.org. 300 IN AAAA 2001:db8::10")
	authNS := mustNewTestRR(t, "example.org. 300 IN NS ns1.example.org.")
	extraTXT := mustNewTestRR(t, "example.org. 300 IN TXT \"tag\"")

	optA := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.DefaultMsgSize, Ttl: 0}}
	optA.SetUDPSize(1232)
	optB := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.DefaultMsgSize, Ttl: 0}}
	optB.SetUDPSize(4096)

	a := new(dns.Msg)
	a.Rcode = dns.RcodeSuccess
	a.Answer = []dns.RR{answerA, answerAAAA}
	a.Ns = []dns.RR{authNS}
	a.Extra = []dns.RR{optA, extraTXT}

	b := new(dns.Msg)
	b.Rcode = dns.RcodeSuccess
	b.Answer = []dns.RR{
		mustNewTestRR(t, "example.org. 42 IN AAAA 2001:db8::10"),
		mustNewTestRR(t, "example.org. 42 IN A 192.0.2.10"),
	}
	b.Ns = []dns.RR{mustNewTestRR(t, "example.org. 42 IN NS ns1.example.org.")}
	b.Extra = []dns.RR{mustNewTestRR(t, "example.org. 42 IN TXT \"tag\""), optB}

	var diff bytes.Buffer
	equivalent := CompareMessage(a, b, &diff)
	if !equivalent {
		t.Fatalf("expected messages to be equivalent, diff:\n%s", diff.String())
	}
	if diff.Len() != 0 {
		t.Fatalf("expected no diff output, got:\n%s", diff.String())
	}
}

func TestCompareMessageDetectsRcodeAndRRDifferences(t *testing.T) {
	t.Parallel()

	a := new(dns.Msg)
	a.Rcode = dns.RcodeSuccess
	a.Answer = []dns.RR{mustNewTestRR(t, "example.org. 300 IN A 192.0.2.10")}
	a.Ns = []dns.RR{mustNewTestRR(t, "example.org. 300 IN NS ns1.example.org.")}

	b := new(dns.Msg)
	b.Rcode = dns.RcodeNameError
	b.Answer = []dns.RR{mustNewTestRR(t, "example.org. 300 IN A 192.0.2.20")}
	b.Ns = []dns.RR{mustNewTestRR(t, "example.org. 300 IN NS ns2.example.org.")}

	var diff bytes.Buffer
	equivalent := CompareMessage(a, b, &diff)
	if equivalent {
		t.Fatalf("expected messages to differ")
	}

	got := diff.String()
	if !strings.Contains(got, "rcode differs") {
		t.Fatalf("expected rcode diff in output, got:\n%s", got)
	}
	if !strings.Contains(got, "answer only in a") {
		t.Fatalf("expected answer diff in output, got:\n%s", got)
	}
	if !strings.Contains(got, "answer only in b") {
		t.Fatalf("expected answer diff in output, got:\n%s", got)
	}
	if !strings.Contains(got, "authority only in a") {
		t.Fatalf("expected authority diff in output, got:\n%s", got)
	}
	if !strings.Contains(got, "authority only in b") {
		t.Fatalf("expected authority diff in output, got:\n%s", got)
	}
}

func TestCompareMessageSafeWithNilParameters(t *testing.T) {
	t.Parallel()

	if !CompareMessage(nil, nil, nil) {
		t.Fatalf("expected nil/nil messages to be equivalent")
	}

	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{mustNewTestRR(t, "example.org. 300 IN A 192.0.2.10")}

	if CompareMessage(nil, msg, nil) {
		t.Fatalf("expected nil/message to differ")
	}

	var diff bytes.Buffer
	if CompareMessage(msg, nil, &diff) {
		t.Fatalf("expected message/nil to differ")
	}
	if diff.Len() == 0 {
		t.Fatalf("expected diff output for message/nil comparison")
	}
}

func mustNewTestRR(tb testing.TB, text string) dns.RR {
	tb.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		tb.Fatalf("dns.NewRR(%q): %v", text, err)
	}
	return rr
}
