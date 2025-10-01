package recursive

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCachePositiveUsesMessageMinTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 2
		tolerance          = 75 * time.Millisecond
	)
	cache := NewCache()
	cache.MinTTL = 0
	cache.MaxTTL = time.Hour
	qname := dns.Fqdn("example-positive-ttl.com")
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    expectedTTLSeconds,
		},
		A: net.IPv4(192, 0, 2, 5),
	})
	cache.DnsSet(msg)
	cq := cache.cq[dns.TypeA]
	cq.mu.RLock()
	entry, ok := cq.cache[qname]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("expected cache entry for %s", qname)
	}
	ttl := time.Until(entry.expires)
	expected := time.Duration(expectedTTLSeconds) * time.Second
	if ttl > expected+tolerance || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
	}
}

func TestCacheNegativeUsesNXTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 12
		tolerance          = 75 * time.Millisecond
	)
	cache := NewCache()
	cache.MinTTL = 0
	cache.NXTTL = time.Duration(expectedTTLSeconds) * time.Second
	qname := dns.Fqdn("example-negative-ttl.org")
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = append(msg.Ns, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:     "ns1.example-negative-ttl.org.",
		Mbox:   "hostmaster.example-negative-ttl.org.",
		Serial: 1,
		Minttl: 900,
	})
	cache.DnsSet(msg)
	cq := cache.cq[dns.TypeAAAA]
	cq.mu.RLock()
	entry, ok := cq.cache[qname]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("expected cache entry for %s", qname)
	}
	ttl := time.Until(entry.expires)
	expected := cache.NXTTL
	if ttl > expected+tolerance || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
	}
}

func newTestMessage(qname string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		},
	}
	return msg
}

func TestCacheHitRatioAndClear(t *testing.T) {
	t.Parallel()

	c := NewCache()
	qname := dns.Fqdn("example.org")

	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d before insert", entries)
	}
	if cached := c.DnsGet(qname, dns.TypeA); cached != nil {
		t.Fatalf("DnsGet returned entry before insert")
	}
	if ratio := c.HitRatio(); ratio != 0 {
		t.Fatalf("HitRatio() = %f before insert", ratio)
	}

	msg := newTestMessage(qname)
	c.DnsSet(msg)

	if entries := c.Entries(); entries != 1 {
		t.Fatalf("Entries() = %d after insert", entries)
	}

	cached := c.DnsGet(qname, dns.TypeA)
	if cached == nil {
		t.Fatalf("DnsGet returned nil after insert")
	}
	if ratio := c.HitRatio(); ratio != 50 {
		t.Fatalf("HitRatio() = %f after first hit", ratio)
	}

	resolved, srv, err := c.DnsResolve(context.Background(), qname, dns.TypeA)
	if err != nil {
		t.Fatalf("DnsResolve error: %v", err)
	}
	if srv.IsValid() {
		t.Fatalf("DnsResolve returned unexpected server %v", srv)
	}
	if resolved == nil {
		t.Fatalf("DnsResolve returned nil message")
	}
	if ratio := c.HitRatio(); ratio <= 60 || ratio >= 70 {
		t.Fatalf("HitRatio() = %f after DnsResolve", ratio)
	}

	c.Clear()
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d after Clear", entries)
	}
}

func TestCacheGetAndCleanRemovesExpired(t *testing.T) {
	t.Parallel()

	c := NewCache()
	qname := dns.Fqdn("expired.example")

	msg := newTestMessage(qname)
	c.cq[dns.TypeA].set(msg, -time.Second)
	if entries := c.Entries(); entries != 1 {
		t.Fatalf("Entries() = %d after expired insert", entries)
	}
	if cached := c.DnsGet(qname, dns.TypeA); cached != nil {
		t.Fatalf("DnsGet returned stale entry")
	}
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d after stale read", entries)
	}

	fresh := newTestMessage(dns.Fqdn("fresh.example"))
	c.cq[dns.TypeA].set(fresh, -time.Minute)
	c.Clean()
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d after Clean", entries)
	}
}
