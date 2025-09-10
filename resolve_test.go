package recursive

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/linkdata/recursive/dnstest"
	"github.com/miekg/dns"
)

func Test_Resolve1111(t *testing.T) {
	DefaultCache = NewCache()

	resps := stubResponses1111()
	dnstestResps := make(map[string]dnstest.Response)
	addrSet := map[string]struct{}{}

	for k, m := range resps {
		dnstestResps[dnstest.Key(k.name, k.qtype)] = dnstest.Response{Msg: m}
		collect := func(rrs []dns.RR) {
			for _, rr := range rrs {
				if a, ok := rr.(*dns.A); ok {
					ip := a.A.String()
					if ip == "1.1.1.1" || ip == "1.0.0.1" {
						continue
					}
					addrSet[ip] = struct{}{}
				}
			}
		}
		collect(m.Answer)
		collect(m.Ns)
		collect(m.Extra)
	}

	addrs := make([]string, 0, len(addrSet)+1)
	addrs = append(addrs, "127.0.1.1")
	for ip := range addrSet {
		addrs = append(addrs, ip)
	}

	servers := make([]*dnstest.Server, 0, len(addrs))
	srv, err := dnstest.NewServer(net.JoinHostPort(addrs[0], "0"), dnstestResps)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	servers = append(servers, srv)
	_, portStr, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	oldPort := dnsPort
	dnsPort = uint16(p)
	defer func() { dnsPort = oldPort }()

	for _, ip := range addrs[1:] {
		srv, err := dnstest.NewServer(net.JoinHostPort(ip, portStr), dnstestResps)
		if err != nil {
			t.Fatalf("start server: %v", err)
		}
		servers = append(servers, srv)
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	roots := []netip.Addr{netip.MustParseAddr(addrs[0])}
	rec := NewWithOptions(nil, NewCache(), roots, nil, nil)

	ctx := context.Background()
	retv, srvAddr, err := rec.DnsResolve(ctx, "one.one.one.one", dns.TypeA)
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
	if !foundit {
		t.Error("did not resolve one.one.one.one to 1.1.1.1")
	}
	if !srvAddr.IsValid() {
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
	if entries := DefaultCache.Entries(); entries == 0 {
		t.Error(entries)
	}
	if hitratio := DefaultCache.HitRatio(); hitratio == 0 {
		t.Error("hit ratio is zero")
	}
}
