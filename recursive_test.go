package recursive

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_Resolve1111(t *testing.T) {
	DefaultCache = NewCache()
	var rec *Recursive
	if networkAvailable() {
		rec = New(nil)
	} else {
		rec = newStubResolver(stubResponses1111())
	}
	ctx := context.Background()

	retv, srv, err := rec.DnsResolve(ctx, "one.one.one.one", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if retv.Rcode != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[retv.Rcode])
	}
	if len(retv.Answer) == 0 {
		t.Fatal("no Answer")
	}
	ipv4 := net.ParseIP("1.1.1.1")
	foundit := false
	for _, rr := range retv.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.Equal(ipv4) {
			foundit = true
			break
		}
	}

	t.Log(retv)
	t.Log(";; SERVER ", srv)

	if !foundit {
		t.Error("did not resolve one.one.one.one to 1.1.1.1")
	}
	if !srv.IsValid() {
		t.Error("did not return server IP")
	}
	if retv.Zero {
		t.Error("expected Z to not be set")
	}

	DefaultCache.DnsSet(retv)
	msg := DefaultCache.DnsGet("one.one.one.one.", dns.TypeA)
	if msg == nil {
		t.Fatal("expected cached message")
	}
	if !msg.Zero {
		t.Error("expected Z to be set")
	}
	entries := DefaultCache.Entries()
	if entries == 0 {
		t.Error(entries)
	}
	hitratio := DefaultCache.HitRatio()
	if hitratio == 0 {
		t.Error("hit ratio is zero")
	}
}

func networkAvailable() bool {
	c, err := net.DialTimeout("tcp", "198.41.0.4:53", time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
