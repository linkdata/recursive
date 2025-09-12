package dnstest

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestServer(t *testing.T) {
	rr, err := dns.NewRR("example.org. 60 IN A 127.0.0.1")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	respMsg := &dns.Msg{Answer: []dns.RR{rr}}

	srv, err := NewServer("127.0.0.1:0", map[string]*Response{
		Key("example.org.", dns.TypeA):      {Msg: respMsg},
		Key("nxdomain.example.", dns.TypeA): {Rcode: dns.RcodeNameError},
		Key("bad.example.", dns.TypeA):      {Raw: []byte{0, 1, 2, 3}},
		Key("timeout.example.", dns.TypeA):  {Drop: true},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	c := dns.Client{Net: "udp"}
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	in, _, err := c.Exchange(req, srv.Addr)
	if err != nil {
		t.Fatalf("udp exchange: %v", err)
	}
	if len(in.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(in.Answer))
	}

	c.Net = "tcp"
	in, _, err = c.Exchange(req, srv.Addr)
	if err != nil {
		t.Fatalf("tcp exchange: %v", err)
	}
	if len(in.Answer) != 1 {
		t.Fatalf("expected 1 tcp answer, got %d", len(in.Answer))
	}

	c.Net = "udp"
	req.SetQuestion("nxdomain.example.", dns.TypeA)
	in, _, err = c.Exchange(req, srv.Addr)
	if err != nil {
		t.Fatalf("nxdomain exchange: %v", err)
	}
	if in.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", in.Rcode)
	}

	req.SetQuestion("bad.example.", dns.TypeA)
	_, _, err = c.Exchange(req, srv.Addr)
	if err == nil {
		t.Fatalf("expected error for bad response")
	}

	c.ReadTimeout = time.Millisecond
	req.SetQuestion("timeout.example.", dns.TypeA)
	_, _, err = c.Exchange(req, srv.Addr)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "timeout") {
		t.Fatalf("expected timeout, got %v", err)
	}
}
