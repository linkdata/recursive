package recursive

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newTestMsg(name string, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP("192.0.2.1")},
	}
	return msg
}

func TestCacheSetGetAndStats(t *testing.T) {
	c := NewCache()
	c.MinTTL = 0
	c.MaxTTL = 60 * time.Second
	msg := newTestMsg("example.org.", 5)
	c.DnsSet(msg)
	if entries := c.Entries(); entries != 1 {
		t.Fatalf("Entries() = %d; want 1", entries)
	}
	if got := c.DnsGet("example.org.", dns.TypeA); got == nil {
		t.Fatalf("DnsGet returned nil")
	}
	if got := c.DnsGet("other.org.", dns.TypeA); got != nil {
		t.Fatalf("DnsGet for missing entry returned %v", got)
	}
	if ratio := c.HitRatio(); ratio != 50 {
		t.Fatalf("HitRatio() = %v; want 50", ratio)
	}
	c.Clear()
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() after Clear = %d; want 0", entries)
	}
}

func TestCacheClean(t *testing.T) {
	c := NewCache()
	c.MinTTL = 0
	c.MaxTTL = -1 * time.Second
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	c.DnsSet(msg)
	if entries := c.Entries(); entries != 1 {
		t.Fatalf("Entries() before Clean = %d; want 1", entries)
	}
	c.Clean()
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() after Clean = %d; want 0", entries)
	}
}

func TestCacheTTLExpiration(t *testing.T) {
	c := NewCache()
	c.MinTTL = 0
	c.MaxTTL = 60 * time.Second
	msg := newTestMsg("example.org.", 0)
	c.DnsSet(msg)
	if entries := c.Entries(); entries != 1 {
		t.Fatalf("Entries() before expiration = %d; want 1", entries)
	}
	if got := c.DnsGet("example.org.", dns.TypeA); got != nil {
		t.Fatalf("DnsGet after expiration returned %v; want nil", got)
	}
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() after expiration = %d; want 0", entries)
	}
}
