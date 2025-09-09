package recursive

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_Resolve1111(t *testing.T) {
	if c, err := net.DialTimeout("tcp", "1.1.1.1:53", time.Second); err != nil {
		t.Skipf("skipping; network unavailable: %v", err)
	} else {
		c.Close()
	}
	rec := New(nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var sb strings.Builder
	retv, srv, err := rec.ResolveWithOptions(ctx, DefaultCache, &sb, "one.one.one.one", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if retv.Rcode != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[retv.Rcode])
	}
	if len(retv.Answer) == 0 {
		t.Fatal("no Answer")
	}
	foundit := false
	for _, rr := range retv.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			if rr.A.Equal(net.ParseIP("1.1.1.1")) {
				foundit = true
				break
			}
		}
	}

	t.Log(retv)
	t.Log(";; SERVER ", srv)
	t.Log(sb.String())

	if !foundit {
		t.Error("did not resolve one.one.one.one to 1.1.1.1")
	}
	if !srv.IsValid() {
		t.Error("did not return server IP")
	}
	if retv.Zero {
		t.Error("expected Z to not be set")
	}

	// do it again, should use the cache
	msg, _, err := rec.DnsResolve(ctx, "one.one.one.one", dns.TypeA)
	if err != nil {
		t.Fatal(err)
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
