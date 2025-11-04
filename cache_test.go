package recursive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
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

func TestCacheWalkVisitsEntries(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	now := time.Now()

	qnameA := dns.Fqdn("walk-a.example")
	msgA := newTestMessage(qnameA)
	expiresA := now.Add(5 * time.Minute)
	cqA := cache.cq[dns.TypeA]
	cqA.mu.Lock()
	cqA.cache[qnameA] = cacheValue{Msg: msgA, expires: expiresA}
	cqA.mu.Unlock()

	qnameAAAA := dns.Fqdn("walk-aaaa.example")
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(qnameAAAA, dns.TypeAAAA)
	msgAAAA.Answer = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: qnameAAAA, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::5"),
		},
	}
	expiresAAAA := now.Add(10 * time.Minute)
	cqAAAA := cache.cq[dns.TypeAAAA]
	cqAAAA.mu.Lock()
	cqAAAA.cache[qnameAAAA] = cacheValue{Msg: msgAAAA, expires: expiresAAAA}
	cqAAAA.mu.Unlock()

	got := make(map[*dns.Msg]time.Time, 2)
	if err := cache.Walk(func(msg *dns.Msg, expires time.Time) error {
		got[msg] = expires
		return nil
	}); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("Walk visited %d entries, expected 2", len(got))
	}
	if exp, ok := got[msgA]; !ok {
		t.Fatalf("Walk did not visit TypeA entry")
	} else if !exp.Equal(expiresA) {
		t.Fatalf("TypeA entry expires %v, expected %v", exp, expiresA)
	}
	if exp, ok := got[msgAAAA]; !ok {
		t.Fatalf("Walk did not visit TypeAAAA entry")
	} else if !exp.Equal(expiresAAAA) {
		t.Fatalf("TypeAAAA entry expires %v, expected %v", exp, expiresAAAA)
	}
}

func TestCacheWalkStopsOnError(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	qname1 := dns.Fqdn("walk-stop-1.example")
	qname2 := dns.Fqdn("walk-stop-2.example")
	msg1 := newTestMessage(qname1)
	msg2 := newTestMessage(qname2)

	cq := cache.cq[dns.TypeA]
	cq.mu.Lock()
	cq.cache[qname1] = cacheValue{Msg: msg1, expires: time.Now().Add(time.Minute)}
	cq.cache[qname2] = cacheValue{Msg: msg2, expires: time.Now().Add(2 * time.Minute)}
	cq.mu.Unlock()

	var calls int
	sentinel := errors.New("stop walk")
	err := cache.Walk(func(msg *dns.Msg, expires time.Time) error {
		calls++
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("Walk returned wrong error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("Walk invoked callback %d times, expected 1", calls)
	}
}

func TestCacheMergeAddsEntries(t *testing.T) {
	t.Parallel()

	dst := NewCache()
	src := NewCache()

	qname := dns.Fqdn("merge-add.example.")
	msg := newTestMessage(qname)
	expires := time.Now().Add(5 * time.Minute)

	srcCQ := src.cq[dns.TypeA]
	srcCQ.mu.Lock()
	srcCQ.cache[qname] = cacheValue{Msg: msg, expires: expires}
	srcCQ.mu.Unlock()

	dst.Merge(src)

	dstCQ := dst.cq[dns.TypeA]
	dstCQ.mu.RLock()
	cv, ok := dstCQ.cache[qname]
	dstCQ.mu.RUnlock()

	if !ok {
		t.Fatalf("expected qname %s to exist after merge", qname)
	}
	if cv.Msg != msg {
		t.Fatalf("merged entry Msg mismatch: got %p want %p", cv.Msg, msg)
	}
	if !cv.expires.Equal(expires) {
		t.Fatalf("merged entry expires %v, expected %v", cv.expires, expires)
	}
}

func TestCacheMergePrefersLatestExpiration(t *testing.T) {
	t.Parallel()

	dst := NewCache()
	src := NewCache()

	qname := dns.Fqdn("merge-conflict.example.")
	now := time.Now()
	shortExpires := now.Add(1 * time.Minute)
	longExpires := now.Add(10 * time.Minute)

	dstCQ := dst.cq[dns.TypeA]
	shortMsg := newTestMessage(qname)
	dstCQ.mu.Lock()
	dstCQ.cache[qname] = cacheValue{Msg: shortMsg, expires: shortExpires}
	dstCQ.mu.Unlock()

	srcCQ := src.cq[dns.TypeA]
	longMsg := newTestMessage(qname)
	srcCQ.mu.Lock()
	srcCQ.cache[qname] = cacheValue{Msg: longMsg, expires: longExpires}
	srcCQ.mu.Unlock()

	dst.Merge(src)

	dstCQ.mu.RLock()
	cv, ok := dstCQ.cache[qname]
	dstCQ.mu.RUnlock()

	if !ok {
		t.Fatalf("expected qname %s to exist after merge", qname)
	}
	if cv.Msg != longMsg {
		t.Fatalf("merge did not replace with longer lived msg")
	}
	if !cv.expires.Equal(longExpires) {
		t.Fatalf("merge expiration mismatch: got %v want %v", cv.expires, longExpires)
	}
}

func TestCacheWriteToReadFromRoundTrip(t *testing.T) {
	t.Parallel()

	src := NewCache()
	base := time.Unix(1_700_000_000, 0).UTC()

	qnameA := dns.Fqdn("serialize-a.example.")
	msgA := newTestMessage(qnameA)
	expiresA := base.Add(5 * time.Minute)
	cqA := src.cq[dns.TypeA]
	cqA.mu.Lock()
	cqA.cache[qnameA] = cacheValue{Msg: msgA, expires: expiresA}
	cqA.mu.Unlock()

	qnameAAAA := dns.Fqdn("serialize-aaaa.example.")
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(qnameAAAA, dns.TypeAAAA)
	msgAAAA.Answer = []dns.RR{
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   qnameAAAA,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			AAAA: net.ParseIP("2001:db8::10"),
		},
	}
	expiresAAAA := base.Add(10 * time.Minute)
	cqAAAA := src.cq[dns.TypeAAAA]
	cqAAAA.mu.Lock()
	cqAAAA.cache[qnameAAAA] = cacheValue{Msg: msgAAAA, expires: expiresAAAA}
	cqAAAA.mu.Unlock()

	var buf bytes.Buffer
	written, err := src.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo returned error: %v", err)
	}
	if written == 0 {
		t.Fatalf("WriteTo wrote zero bytes")
	}

	dst := NewCache()
	read, err := dst.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if read != written {
		t.Fatalf("ReadFrom read %d bytes, want %d", read, written)
	}

	assertEntry := func(t *testing.T, qtype uint16, qname string, wantExpires time.Time) {
		t.Helper()
		cq := dst.cq[qtype]
		cq.mu.RLock()
		cv, ok := cq.cache[qname]
		cq.mu.RUnlock()
		if !ok {
			t.Fatalf("missing cache entry for %s qtype=%d", qname, qtype)
		}
		if cv.Msg == nil || len(cv.Msg.Question) == 0 || cv.Msg.Question[0].Name != qname {
			t.Fatalf("unexpected message for %s: %#v", qname, cv.Msg)
		}
		if !cv.expires.Equal(wantExpires) {
			t.Fatalf("expires mismatch for %s: got %v want %v", qname, cv.expires, wantExpires)
		}
	}

	assertEntry(t, dns.TypeA, qnameA, expiresA)
	assertEntry(t, dns.TypeAAAA, qnameAAAA, expiresAAAA)
}

func TestCacheWriteToReadFromErrorPropagation(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel write/read failure")

	t.Run("write", func(t *testing.T) {
		t.Parallel()
		cache := NewCache()
		writer := &failWriter{failAfter: 1, err: sentinel}
		if _, err := cache.WriteTo(writer); !errors.Is(err, sentinel) {
			t.Fatalf("WriteTo error = %v, want %v", err, sentinel)
		}
		if writer.writes != writer.failAfter {
			t.Fatalf("WriteTo performed unexpected number of writes: %d", writer.writes)
		}
	})

	t.Run("read", func(t *testing.T) {
		t.Parallel()
		cache := NewCache()
		var b []byte
		b = binary.BigEndian.AppendUint64(b, magic)
		b = binary.BigEndian.AppendUint64(b, 0)
		goodPrefix := bytes.NewReader(b)
		reader := io.MultiReader(goodPrefix, &failReader{err: sentinel})
		if _, err := cache.ReadFrom(reader); !errors.Is(err, sentinel) {
			t.Fatalf("ReadFrom error = %v, want %v", err, sentinel)
		}
	})
}

type failWriter struct {
	failAfter int
	writes    int
	err       error
}

func (fw *failWriter) Write(p []byte) (int, error) {
	if fw.writes >= fw.failAfter {
		return 0, fw.err
	}
	fw.writes++
	return len(p), nil
}

type failReader struct {
	err error
}

func (fr *failReader) Read(p []byte) (int, error) {
	return 0, fr.err
}
