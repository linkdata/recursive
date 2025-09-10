package recursive

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestResolveWithOptionsErrQuestionMismatch(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Question[0] = dns.Question{Name: "other.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		_ = w.WriteMsg(m)
	})
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	srv := &dns.Server{PacketConn: udpConn, Handler: handler}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	oldPort := dnsPort
	dnsPort = uint16(port)
	defer func() { dnsPort = oldPort }()

	r := NewWithOptions(nil, nil, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil, nil)
	_, _, err = r.ResolveWithOptions(context.Background(), nil, nil, "example.org.", dns.TypeA)
	if !errors.Is(err, ErrQuestionMismatch) {
		t.Fatalf("err = %v; want ErrQuestionMismatch", err)
	}
}
