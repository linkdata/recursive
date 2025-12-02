package recursive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCachePositiveUsesMessageMinTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 2
		tolerance          = 1
	)
	cache := NewCache()
	cache.MinTTL = 0
	cache.MaxTTL = 60 * 60
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
	key := mustBucketKey(t, qname, dns.TypeA)
	cq := cache.bucketFor(key)
	cq.mu.RLock()
	entry, ok := cq.cache[key]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("expected cache entry for %s", qname)
	}
	ttl := int64(time.Until(time.Unix(entry.expires, 0)).Seconds())
	if ttl > expectedTTLSeconds+tolerance || ttl < expectedTTLSeconds-tolerance {
		t.Fatalf("unexpected ttl got=%v want=%v±%v", ttl, expectedTTLSeconds, tolerance)
	}
}

func TestCacheNegativeUsesNXTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 12
		tolerance          = 1
	)
	cache := NewCache()
	cache.MinTTL = 0
	cache.NXTTL = expectedTTLSeconds
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
	key := mustBucketKey(t, qname, dns.TypeAAAA)
	cq := cache.bucketFor(key)
	cq.mu.RLock()
	entry, ok := cq.cache[key]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("expected cache entry for %s", qname)
	}
	ttl := int64(time.Until(time.Unix(entry.expires, 0)).Seconds())
	expected := cache.NXTTL
	if ttl > expected+tolerance || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%v want=%v±%v", ttl, expected, tolerance)
	}
}

func newTestMessage(qname string) *dns.Msg {
	return newTestMessageForType(nil, dns.TypeA, qname, 0)
}

func newCacheWithEntries(t *testing.T, entries int) *Cache {
	t.Helper()

	cache := NewCache()
	if entries <= 0 {
		return cache
	}

	aCount := int(math.Ceil(float64(entries) * 0.9))
	if aCount > entries {
		aCount = entries
	}
	remaining := entries - aCount
	counts := map[uint16]int{
		dns.TypeA:     aCount,
		dns.TypeNS:    0,
		dns.TypeAAAA:  0,
		dns.TypeCNAME: 0,
	}
	if remaining > 0 {
		perType := remaining / 3
		counts[dns.TypeNS] = perType
		counts[dns.TypeAAAA] = perType
		counts[dns.TypeCNAME] = perType
		switch remaining % 3 {
		case 2:
			counts[dns.TypeAAAA]++
			fallthrough
		case 1:
			counts[dns.TypeNS]++
		}
	}

	qtypes := []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA, dns.TypeCNAME}
	entryIdx := 0
	for _, qt := range qtypes {
		for i := 0; i < counts[qt]; i++ {
			prefix := fmt.Sprintf("%cgen%d", 'a'+(entryIdx%26), entryIdx/26)
			qname := dns.Fqdn(fmt.Sprintf("%s-cache-%s-%d.example", prefix, dns.Type(qt), entryIdx))
			cache.DnsSet(newTestMessageForType(t, qt, qname, entryIdx))
			entryIdx++
		}
	}

	return cache
}

func newTestMessageForType(t *testing.T, qtype uint16, qname string, idx int) *dns.Msg {
	if t != nil {
		t.Helper()
	}

	const ttl = 300
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	hdr := dns.RR_Header{
		Name:   qname,
		Rrtype: qtype,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}

	switch qtype {
	case dns.TypeA:
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: hdr,
				A:   net.IPv4(192, 0, 2, byte((idx%250)+1)),
			},
		}
	case dns.TypeAAAA:
		ip := net.ParseIP(fmt.Sprintf("2001:db8::%x", idx+1))
		if ip == nil {
			if t != nil {
				t.Fatalf("failed to parse ipv6 address for index %d", idx)
			}
			panic(fmt.Sprintf("failed to parse ipv6 address for index %d", idx))
		}
		msg.Answer = []dns.RR{
			&dns.AAAA{
				Hdr:  hdr,
				AAAA: ip,
			},
		}
	case dns.TypeNS:
		msg.Answer = []dns.RR{
			&dns.NS{
				Hdr: hdr,
				Ns:  dns.Fqdn(fmt.Sprintf("ns-%d.example", idx+1)),
			},
		}
	case dns.TypeCNAME:
		msg.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    hdr,
				Target: dns.Fqdn(fmt.Sprintf("alias-%d.example", idx+1)),
			},
		}
	default:
		if t != nil {
			t.Fatalf("unsupported qtype %d", qtype)
		}
		panic(fmt.Sprintf("unsupported qtype %d", qtype))
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
	key := mustBucketKey(t, qname, dns.TypeA)
	c.bucketFor(key).set(key, msg, -1)
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
	freshKey := mustBucketKey(t, dns.Fqdn("fresh.example"), dns.TypeA)
	c.bucketFor(freshKey).set(freshKey, fresh, -60)
	c.Clean()
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d after Clean", entries)
	}
}

func TestCacheWalkVisitsEntries(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	now := time.Now().Unix()

	qnameA := dns.Fqdn("walk-a.example")
	msgA := newTestMessage(qnameA)
	expiresA := now + (5 * 60)
	keyA := mustBucketKey(t, qnameA, dns.TypeA)
	cqA := cache.bucketFor(keyA)
	cqA.mu.Lock()
	cqA.cache[keyA] = cacheValue{Msg: msgA, expires: expiresA}
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
	expiresAAAA := now + (10 * 60)
	keyAAAA := mustBucketKey(t, qnameAAAA, dns.TypeAAAA)
	cqAAAA := cache.bucketFor(keyAAAA)
	cqAAAA.mu.Lock()
	cqAAAA.cache[keyAAAA] = cacheValue{Msg: msgAAAA, expires: expiresAAAA}
	cqAAAA.mu.Unlock()

	got := make(map[*dns.Msg]int64, 2)
	if err := cache.Walk(func(msg *dns.Msg, expires time.Time) error {
		got[msg] = expires.Unix()
		return nil
	}); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("Walk visited %d entries, expected 2", len(got))
	}
	if exp, ok := got[msgA]; !ok {
		t.Fatalf("Walk did not visit TypeA entry")
	} else if exp != expiresA {
		t.Fatalf("TypeA entry expires %v, expected %v", exp, expiresA)
	}
	if exp, ok := got[msgAAAA]; !ok {
		t.Fatalf("Walk did not visit TypeAAAA entry")
	} else if exp != expiresAAAA {
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

	now := time.Now().Unix()
	key1 := mustBucketKey(t, qname1, dns.TypeA)
	cq1 := cache.bucketFor(key1)
	cq1.mu.Lock()
	cq1.cache[key1] = cacheValue{Msg: msg1, expires: now + 60}
	cq1.mu.Unlock()

	key2 := mustBucketKey(t, qname2, dns.TypeA)
	cq2 := cache.bucketFor(key2)
	cq2.mu.Lock()
	cq2.cache[key2] = cacheValue{Msg: msg2, expires: now + (2 * 60)}
	cq2.mu.Unlock()

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
	expires := time.Now().Add(5 * 60)
	wantExpires := expires.Unix()

	key := mustBucketKey(t, qname, dns.TypeA)
	srcCQ := src.bucketFor(key)
	srcCQ.mu.Lock()
	srcCQ.cache[key] = cacheValue{Msg: msg, expires: wantExpires}
	srcCQ.mu.Unlock()

	dst.Merge(src)

	dstCQ := dst.bucketFor(key)
	dstCQ.mu.RLock()
	cv, ok := dstCQ.cache[key]
	dstCQ.mu.RUnlock()

	if !ok {
		t.Fatalf("expected qname %s to exist after merge", qname)
	}
	if cv.Msg != msg {
		t.Fatalf("merged entry Msg mismatch: got %p want %p", cv.Msg, msg)
	}
	if cv.expires != wantExpires {
		t.Fatalf("merged entry expires %v, expected %v", cv.expires, expires)
	}
}

func TestCacheMergePrefersLatestExpiration(t *testing.T) {
	t.Parallel()

	dst := NewCache()
	src := NewCache()

	qname := dns.Fqdn("merge-conflict.example.")
	now := time.Now().Unix()
	shortExpires := now + (1 * 60)
	longExpires := now + (10 * 60)

	key := mustBucketKey(t, qname, dns.TypeA)
	dstCQ := dst.bucketFor(key)
	shortMsg := newTestMessage(qname)
	dstCQ.mu.Lock()
	dstCQ.cache[key] = cacheValue{Msg: shortMsg, expires: shortExpires}
	dstCQ.mu.Unlock()

	srcCQ := src.bucketFor(key)
	longMsg := newTestMessage(qname)
	srcCQ.mu.Lock()
	srcCQ.cache[key] = cacheValue{Msg: longMsg, expires: longExpires}
	srcCQ.mu.Unlock()

	dst.Merge(src)

	dstCQ.mu.RLock()
	cv, ok := dstCQ.cache[key]
	dstCQ.mu.RUnlock()

	if !ok {
		t.Fatalf("expected qname %s to exist after merge", qname)
	}
	if cv.Msg != longMsg {
		t.Fatalf("merge did not replace with longer lived msg")
	}
	if cv.expires != longExpires {
		t.Fatalf("merge expiration mismatch: got %v want %v", cv.expires, longExpires)
	}
}

func TestCacheWriteToReadFromRoundTrip(t *testing.T) {
	t.Parallel()

	src := NewCache()
	base := int64(1_700_000_000)

	qnameA := dns.Fqdn("serialize-a.example.")
	msgA := newTestMessage(qnameA)
	expiresA := base + (5 * 60)
	keyA := mustBucketKey(t, qnameA, dns.TypeA)
	cqA := src.bucketFor(keyA)
	cqA.mu.Lock()
	cqA.cache[keyA] = cacheValue{Msg: msgA, expires: expiresA}
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
	expiresAAAA := base + (10 * 60)
	keyAAAA := mustBucketKey(t, qnameAAAA, dns.TypeAAAA)
	cqAAAA := src.bucketFor(keyAAAA)
	cqAAAA.mu.Lock()
	cqAAAA.cache[keyAAAA] = cacheValue{Msg: msgAAAA, expires: expiresAAAA}
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

	assertEntry := func(t *testing.T, qtype uint16, qname string, wantExpires int64) {
		t.Helper()
		key := mustBucketKey(t, qname, qtype)
		cq := dst.bucketFor(key)
		cq.mu.RLock()
		cv, ok := cq.cache[key]
		cq.mu.RUnlock()
		if !ok {
			t.Fatalf("missing cache entry for %s qtype=%d", qname, qtype)
		}
		if cv.Msg == nil || len(cv.Msg.Question) == 0 || cv.Msg.Question[0].Name != qname {
			t.Fatalf("unexpected message for %s: %#v", qname, cv.Msg)
		}
		if cv.expires != wantExpires {
			t.Fatalf("expires mismatch for %s: got %v want %v", qname, cv.expires, wantExpires)
		}
	}

	assertEntry(t, dns.TypeA, qnameA, expiresA)
	assertEntry(t, dns.TypeAAAA, qnameAAAA, expiresAAAA)
}

func TestCacheWriteToReadFromHandlesShortReads(t *testing.T) {
	t.Parallel()

	const chunkSize = 16

	src := NewCache()
	qnameTXT := dns.Fqdn("serialize-shortread.example.")
	txtPayload := strings.Repeat("chunky", 40) // 240 bytes to guarantee a larger packet
	msgTXT := new(dns.Msg)
	msgTXT.SetQuestion(qnameTXT, dns.TypeTXT)
	msgTXT.Answer = []dns.RR{
		&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   qnameTXT,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    900,
			},
			Txt: []string{txtPayload},
		},
	}
	if msgTXT.Len() <= chunkSize {
		t.Fatalf("test requires message larger than chunk size, got len=%d chunk=%d", msgTXT.Len(), chunkSize)
	}
	expiresTXT := int64(1_700_000_000) + (15 * 60)
	key := mustBucketKey(t, qnameTXT, dns.TypeTXT)
	cqTXT := src.bucketFor(key)
	cqTXT.mu.Lock()
	cqTXT.cache[key] = cacheValue{Msg: msgTXT, expires: expiresTXT}
	cqTXT.mu.Unlock()

	var buf bytes.Buffer
	written, err := src.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo returned error: %v", err)
	}
	if written == 0 {
		t.Fatal("WriteTo wrote zero bytes")
	}

	dst := NewCache()
	chunked := &chunkedReader{
		r:     bytes.NewReader(buf.Bytes()),
		chunk: chunkSize,
	}
	read, err := dst.ReadFrom(chunked)
	if err != nil {
		t.Fatalf("ReadFrom should tolerate short reads, got error: %v", err)
	}
	if read != written {
		t.Fatalf("ReadFrom read %d bytes, want %d", read, written)
	}

	cq := dst.bucketFor(key)
	cq.mu.RLock()
	cv, ok := cq.cache[key]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("missing cache entry for %s after short-read roundtrip", qnameTXT)
	}
	if cv.Msg == nil || len(cv.Msg.Question) == 0 || cv.Msg.Question[0].Name != qnameTXT {
		t.Fatalf("unexpected message for %s: %#v", qnameTXT, cv.Msg)
	}
	if cv.expires != expiresTXT {
		t.Fatalf("expires mismatch for %s: got %v want %v", qnameTXT, cv.expires, expiresTXT)
	}
}

type chunkedReader struct {
	r     io.Reader
	chunk int
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.chunk <= 0 {
		return cr.r.Read(p)
	}
	if len(p) > cr.chunk {
		p = p[:cr.chunk]
	}
	return cr.r.Read(p)
}

func FuzzCacheWriteReadRoundTrip(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(5)
	f.Add(50)
	f.Add(200)

	f.Fuzz(func(t *testing.T, entries int) {
		t.Helper()

		if entries < 0 {
			entries = -entries
		}
		if entries > 500 {
			entries = entries % 500
		}

		src := newCacheWithEntries(t, entries)

		tmp := filepath.Join(t.TempDir(), "dnscache.bin")
		file, err := os.Create(tmp)
		if err != nil {
			t.Fatalf("Create temp cache file: %v", err)
		}
		defer os.Remove(tmp)

		written, err := src.WriteTo(file)
		file.Close()
		if err != nil {
			t.Fatalf("WriteTo returned error: %v", err)
		}
		if written <= 0 {
			t.Fatalf("WriteTo wrote zero bytes for %d entries", entries)
		}

		dst := NewCache()
		readFile, err := os.Open(tmp)
		if err != nil {
			t.Fatalf("Open temp cache file for read: %v", err)
		}
		read, err := dst.ReadFrom(readFile)
		readFile.Close()
		if err != nil {
			t.Fatalf("ReadFrom returned error: %v", err)
		}
		if read != written {
			t.Fatalf("ReadFrom read %d bytes, want %d", read, written)
		}

		assertCachesEqual(t, src, dst)
	})
}

func assertCachesEqual(t *testing.T, want, got *Cache) {
	t.Helper()

	if wantEntries, gotEntries := want.Entries(), got.Entries(); wantEntries != gotEntries {
		t.Fatalf("cache entry count mismatch: got %d want %d", gotEntries, wantEntries)
	}

	wantSnapshot := snapshotCache(want)
	gotSnapshot := snapshotCache(got)

	if len(wantSnapshot) != len(gotSnapshot) {
		t.Fatalf("cache entry count mismatch after snapshot: got %d want %d", len(gotSnapshot), len(wantSnapshot))
	}

	for key, wantCV := range wantSnapshot {
		gotCV, ok := gotSnapshot[key]
		if !ok {
			t.Fatalf("missing qname %s qtype %d", key.qname, key.qtype)
		}
		if wantCV.expires != gotCV.expires {
			t.Fatalf("qname %s qtype %d expires mismatch: got %d want %d", key.qname, key.qtype, gotCV.expires, wantCV.expires)
		}
		if !dnsMsgsEqual(wantCV.Msg, gotCV.Msg) {
			t.Fatalf("qname %s qtype %d message mismatch:\nwant:\n%s\ngot:\n%s", key.qname, key.qtype, wantCV.Msg, gotCV.Msg)
		}
	}
}

func snapshotCache(c *Cache) map[bucketKey]cacheValue {
	out := make(map[bucketKey]cacheValue)
	for _, bucket := range c.cq {
		bucket.mu.RLock()
		for key, cv := range bucket.cache {
			out[key] = cv
		}
		bucket.mu.RUnlock()
	}
	return out
}

func mustBucketKey(t *testing.T, qname string, qtype uint16) (key bucketKey) {
	t.Helper()
	key = newBucketKey(qname, qtype)
	return
}

func dnsMsgsEqual(a, b *dns.Msg) bool {
	if a == nil || b == nil {
		return a == b
	}
	if reflect.DeepEqual(a, b) {
		return true
	}
	return a.String() == b.String()
}
