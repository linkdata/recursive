package recursive_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/linkdata/recursive"
	"github.com/miekg/dns"
)

func Test_Resolve1111(t *testing.T) {
	rec := recursive.New(nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var sb strings.Builder
	retv, _, err := rec.ResolveWithOptions(ctx, recursive.DefaultCache, &sb, "one.one.one.one", dns.TypeA)
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
	if !foundit {
		t.Log(sb.String())
		t.Log(retv)
		t.Error("did not resolve one.one.one.one to 1.1.1.1")
	}
}
