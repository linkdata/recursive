package recursive

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type stubKey struct {
	name  string
	qtype uint16
}

type stubDialer struct {
	responses map[stubKey]*dns.Msg
}

func (d *stubDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	isTCP := len(network) >= 3 && network[:3] == "tcp"
	return &stubConn{dialer: d, isTCP: isTCP}, nil
}

type stubConn struct {
	dialer *stubDialer
	isTCP  bool
	buf    bytes.Buffer
}

func (c *stubConn) Read(p []byte) (int, error) { return c.buf.Read(p) }

func (c *stubConn) Write(p []byte) (int, error) {
	origN := len(p)
	if c.isTCP {
		if len(p) < 2 {
			return 0, io.ErrShortWrite
		}
		ln := int(binary.BigEndian.Uint16(p[:2]))
		p = p[2 : 2+ln]
	}
	var m dns.Msg
	if err := m.Unpack(p); err != nil {
		return 0, err
	}
	name := dns.CanonicalName(m.Question[0].Name)
	qtype := m.Question[0].Qtype
	key := stubKey{name, qtype}
	resp, ok := c.dialer.responses[key]
	if !ok {
		resp = new(dns.Msg)
		resp.SetRcode(&m, dns.RcodeServerFailure)
	} else {
		resp = resp.Copy()
		if len(resp.Question) == 0 {
			resp.SetQuestion(name, qtype)
		}
		resp.Id = m.Id
	}
	packed, err := resp.Pack()
	if err != nil {
		return 0, err
	}
	c.buf.Reset()
	if c.isTCP {
		var lenbuf [2]byte
		binary.BigEndian.PutUint16(lenbuf[:], uint16(len(packed)))
		c.buf.Write(lenbuf[:])
	}
	c.buf.Write(packed)
	return origN, nil
}

func (c *stubConn) Close() error                       { return nil }
func (c *stubConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *stubConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *stubConn) SetDeadline(t time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

func aRR(name, ip string) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 86400}, A: net.ParseIP(ip)}
}

func nsRR(name, ns string) dns.RR {
	return &dns.NS{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400}, Ns: dns.Fqdn(ns)}
}

func newStubResolver(resps map[stubKey]*dns.Msg) *Recursive {
	dialer := &stubDialer{responses: resps}
	return NewWithOptions(dialer, NewCache(), nil, nil, nil)
}

func stubResponses1111() map[stubKey]*dns.Msg {
	responses := map[stubKey]*dns.Msg{}
	// Root: NS one.
	responses[stubKey{"one.", dns.TypeNS}] = &dns.Msg{
		Ns: []dns.RR{
			nsRR("one.", "a.nic.one."),
			nsRR("one.", "b.nic.one."),
			nsRR("one.", "c.nic.one."),
			nsRR("one.", "x.nic.one."),
		},
		Extra: []dns.RR{
			aRR("a.nic.one.", "127.0.1.2"),
			aRR("b.nic.one.", "127.0.1.3"),
			aRR("c.nic.one.", "127.0.1.4"),
			aRR("x.nic.one.", "127.0.1.5"),
		},
	}
	// a.nic.one.: NS one.one.
	responses[stubKey{"one.one.", dns.TypeNS}] = &dns.Msg{
		Ns: []dns.RR{
			nsRR("one.one.", "auth.g1-dns.one."),
			nsRR("one.one.", "auth.g1-dns.com."),
		},
		Extra: []dns.RR{
			aRR("auth.g1-dns.one.", "127.0.1.6"),
		},
	}
	// auth.g1-dns.one.: NS one.one.one.
	responses[stubKey{"one.one.one.", dns.TypeNS}] = &dns.Msg{
		Ns: []dns.RR{
			nsRR("one.one.one.", "dorthy.ns.cloudflare.com."),
			nsRR("one.one.one.", "terin.ns.cloudflare.com."),
		},
	}
	// glue lookups
	responses[stubKey{"com.", dns.TypeA}] = &dns.Msg{
		Ns: []dns.RR{
			nsRR("com.", "a.gtld-servers.net."),
			nsRR("com.", "b.gtld-servers.net."),
			nsRR("com.", "c.gtld-servers.net."),
			nsRR("com.", "d.gtld-servers.net."),
		},
		Extra: []dns.RR{
			aRR("a.gtld-servers.net.", "127.0.1.7"),
			aRR("b.gtld-servers.net.", "127.0.1.8"),
			aRR("c.gtld-servers.net.", "127.0.1.9"),
			aRR("d.gtld-servers.net.", "127.0.1.10"),
		},
	}
	responses[stubKey{"cloudflare.com.", dns.TypeA}] = &dns.Msg{
		Ns: []dns.RR{
			nsRR("cloudflare.com.", "ns3.cloudflare.com."),
			nsRR("cloudflare.com.", "ns4.cloudflare.com."),
			nsRR("cloudflare.com.", "ns5.cloudflare.com."),
			nsRR("cloudflare.com.", "ns6.cloudflare.com."),
		},
		Extra: []dns.RR{
			aRR("ns3.cloudflare.com.", "127.0.1.11"),
			aRR("ns4.cloudflare.com.", "127.0.1.12"),
			aRR("ns5.cloudflare.com.", "127.0.1.13"),
			aRR("ns6.cloudflare.com.", "127.0.1.14"),
		},
	}
	responses[stubKey{"ns.cloudflare.com.", dns.TypeA}] = &dns.Msg{
		Answer: []dns.RR{
			aRR("ns.cloudflare.com.", "127.0.1.15"),
			aRR("ns.cloudflare.com.", "127.0.1.16"),
		},
	}
	responses[stubKey{"dorthy.ns.cloudflare.com.", dns.TypeA}] = &dns.Msg{
		Answer: []dns.RR{
			aRR("dorthy.ns.cloudflare.com.", "127.0.1.17"),
		},
	}
	responses[stubKey{"terin.ns.cloudflare.com.", dns.TypeA}] = &dns.Msg{
		Answer: []dns.RR{
			aRR("terin.ns.cloudflare.com.", "127.0.1.18"),
		},
	}
	// Final NS for one.one.one.one.
	responses[stubKey{"one.one.one.one.", dns.TypeNS}] = &dns.Msg{
		Ns: []dns.RR{
			nsRR("one.one.one.one.", "dorthy.ns.cloudflare.com."),
			nsRR("one.one.one.one.", "terin.ns.cloudflare.com."),
		},
	}
	// Final A answer
	finalA := &dns.Msg{
		Answer: []dns.RR{
			aRR("one.one.one.one.", "1.1.1.1"),
			aRR("one.one.one.one.", "1.0.0.1"),
		},
	}
	finalA.Authoritative = true
	responses[stubKey{"one.one.one.one.", dns.TypeA}] = finalA
	return responses
}

func TestStubResolverSimulates1111(t *testing.T) {
	rec := newStubResolver(stubResponses1111())
	ctx := context.Background()
	msg, _, err := rec.DnsResolve(ctx, "one.one.one.one", dns.TypeA)
	if err != nil {
		t.Fatalf("DnsResolve error: %v", err)
	}
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%v", msg.Rcode)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(msg.Answer))
	}
	got1 := msg.Answer[0].(*dns.A).A.String()
	got2 := msg.Answer[1].(*dns.A).A.String()
	if (got1 != "1.1.1.1" || got2 != "1.0.0.1") && (got1 != "1.0.0.1" || got2 != "1.1.1.1") {
		t.Fatalf("unexpected answers: %v %v", got1, got2)
	}
}
