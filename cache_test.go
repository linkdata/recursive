package recursive

import (
	"bufio"
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
		tolerance          = time.Second + 75*time.Millisecond
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
	ttl := time.Until(time.Unix(entry.expires, 0))
	expected := time.Duration(expectedTTLSeconds) * time.Second
	if ttl > expected+tolerance || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
	}
}

func TestCacheNegativeUsesNXTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 12
		tolerance          = time.Second + 75*time.Millisecond
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
	ttl := time.Until(time.Unix(entry.expires, 0))
	expected := cache.NXTTL
	if ttl > expected+tolerance || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
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
	cqA.cache[qnameA] = cacheValue{Msg: msgA, expires: expiresA.Unix()}
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
	cqAAAA.cache[qnameAAAA] = cacheValue{Msg: msgAAAA, expires: expiresAAAA.Unix()}
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
	} else if !exp.Equal(time.Unix(expiresA.Unix(), 0)) {
		t.Fatalf("TypeA entry expires %v, expected %v", exp, time.Unix(expiresA.Unix(), 0))
	}
	if exp, ok := got[msgAAAA]; !ok {
		t.Fatalf("Walk did not visit TypeAAAA entry")
	} else if !exp.Equal(time.Unix(expiresAAAA.Unix(), 0)) {
		t.Fatalf("TypeAAAA entry expires %v, expected %v", exp, time.Unix(expiresAAAA.Unix(), 0))
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
	cq.cache[qname1] = cacheValue{Msg: msg1, expires: time.Now().Add(time.Minute).Unix()}
	cq.cache[qname2] = cacheValue{Msg: msg2, expires: time.Now().Add(2 * time.Minute).Unix()}
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
	wantExpires := expires.Unix()

	srcCQ := src.cq[dns.TypeA]
	srcCQ.mu.Lock()
	srcCQ.cache[qname] = cacheValue{Msg: msg, expires: wantExpires}
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
	if cv.expires != wantExpires {
		t.Fatalf("merged entry expires %v, expected %v", time.Unix(cv.expires, 0), expires)
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
	shortExpiresUnix := shortExpires.Unix()
	longExpiresUnix := longExpires.Unix()

	dstCQ := dst.cq[dns.TypeA]
	shortMsg := newTestMessage(qname)
	dstCQ.mu.Lock()
	dstCQ.cache[qname] = cacheValue{Msg: shortMsg, expires: shortExpiresUnix}
	dstCQ.mu.Unlock()

	srcCQ := src.cq[dns.TypeA]
	longMsg := newTestMessage(qname)
	srcCQ.mu.Lock()
	srcCQ.cache[qname] = cacheValue{Msg: longMsg, expires: longExpiresUnix}
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
	if cv.expires != longExpiresUnix {
		t.Fatalf("merge expiration mismatch: got %v want %v", time.Unix(cv.expires, 0), longExpires)
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
	cqA.cache[qnameA] = cacheValue{Msg: msgA, expires: expiresA.Unix()}
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
	cqAAAA.cache[qnameAAAA] = cacheValue{Msg: msgAAAA, expires: expiresAAAA.Unix()}
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
		if cv.expires != wantExpires.Unix() {
			t.Fatalf("expires mismatch for %s: got %v want %v", qname, time.Unix(cv.expires, 0), wantExpires)
		}
	}

	assertEntry(t, dns.TypeA, qnameA, expiresA)
	assertEntry(t, dns.TypeAAAA, qnameAAAA, expiresAAAA)
}

func TestCacheWriteToReadFromHandlesShortReads(t *testing.T) {
	t.Parallel()

	const chunkSize = 16

	src := NewCache()
	base := time.Unix(1_700_000_000, 0).UTC()

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
	expiresTXT := base.Add(15 * time.Minute)
	cqTXT := src.cq[dns.TypeTXT]
	cqTXT.mu.Lock()
	cqTXT.cache[qnameTXT] = cacheValue{Msg: msgTXT, expires: expiresTXT.Unix()}
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

	cq := dst.cq[dns.TypeTXT]
	cq.mu.RLock()
	cv, ok := cq.cache[qnameTXT]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("missing cache entry for %s after short-read roundtrip", qnameTXT)
	}
	if cv.Msg == nil || len(cv.Msg.Question) == 0 || cv.Msg.Question[0].Name != qnameTXT {
		t.Fatalf("unexpected message for %s: %#v", qnameTXT, cv.Msg)
	}
	if cv.expires != expiresTXT.Unix() {
		t.Fatalf("expires mismatch for %s: got %v want %v", qnameTXT, time.Unix(cv.expires, 0), expiresTXT)
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

	for qtype := range want.cq {
		wantSnapshot := snapshotCacheQtype(want.cq[qtype])
		gotSnapshot := snapshotCacheQtype(got.cq[qtype])

		if len(wantSnapshot) != len(gotSnapshot) {
			t.Fatalf("qtype %d entry count mismatch: got %d want %d", qtype, len(gotSnapshot), len(wantSnapshot))
		}

		for qname, wantCV := range wantSnapshot {
			gotCV, ok := gotSnapshot[qname]
			if !ok {
				t.Fatalf("qtype %d missing qname %s", qtype, qname)
			}
			if wantCV.expires != gotCV.expires {
				t.Fatalf("qtype %d qname %s expires mismatch: got %d want %d", qtype, qname, gotCV.expires, wantCV.expires)
			}
			if !dnsMsgsEqual(wantCV.Msg, gotCV.Msg) {
				t.Fatalf("qtype %d qname %s message mismatch:\nwant:\n%s\ngot:\n%s", qtype, qname, wantCV.Msg, gotCV.Msg)
			}
		}
	}
}

func snapshotCacheQtype(cq *cacheQtype) map[string]cacheValue {
	cq.mu.RLock()
	defer cq.mu.RUnlock()

	out := make(map[string]cacheValue, len(cq.cache))
	for k, v := range cq.cache {
		out[k] = v
	}
	return out
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

func TestCacheWriteTo(t *testing.T) {
	c, _, err := loadCacheFile(t, "dnscache1.bin")
	if err == nil {
		saveCacheFile(t, c, "dnscache2-*.bin")
		saveCacheFileWriteTo(t, "dnscache1-*.bin", c.WriteToV1)
	}
}

func loadCacheFile(t *testing.T, fixture string) (c *Cache, elapsed time.Duration, err error) {
	if t != nil {
		t.Helper()
	}
	var source *os.File
	if source, err = os.Open(fixture); err == nil {
		defer source.Close()
		c = NewCache()
		start := time.Now()
		var n int64
		n, err = c.ReadFrom(bufio.NewReader(source))
		elapsed = time.Since(start)
		if t != nil {
			t.Logf("loadCacheFile %q: %s (%v bytes)\n", fixture, elapsed, n)
		}
	}
	return
}

func saveCacheFileWriteTo(t *testing.T, fixture string, writeTo func(w io.Writer) (n int64, err error)) (fpath string, elapsed time.Duration, err error) {
	if t != nil {
		t.Helper()
	}
	var f *os.File
	if f, err = os.CreateTemp("", fixture); err == nil {
		defer f.Close()
		fpath = f.Name()
		bw := bufio.NewWriter(f)
		defer bw.Flush()
		start := time.Now()
		var n int64
		n, err = writeTo(bw)
		elapsed = time.Since(start)
		if t != nil {
			t.Logf("saveCacheFile %q: %s (%v bytes)\n", fpath, elapsed, n)
		}
	}
	return
}

func saveCacheFile(t *testing.T, c *Cache, fixture string) (fpath string, elapsed time.Duration, err error) {
	if t != nil {
		t.Helper()
	}
	return saveCacheFileWriteTo(t, fixture, c.WriteTo)
}
