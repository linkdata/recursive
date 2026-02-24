package recursive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/netip"
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
	entry := mustCacheValue(t, cache, qname, dns.TypeA)
	assertTTLWithin(t, entry, expectedTTLSeconds, tolerance)
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
	entry := mustCacheValue(t, cache, qname, dns.TypeAAAA)
	assertTTLWithin(t, entry, int64(cache.NXTTL), tolerance)
}

func TestCacheDnsGetReturnsRemainingTTL(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	cache.MinTTL = 0
	qname := dns.Fqdn("ttl-adjust.example.")

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    4,
		},
		A: net.IPv4(192, 0, 2, 10),
	})

	cache.DnsSet(msg)
	time.Sleep(time.Second)

	cached := cache.DnsGet(qname, dns.TypeA)
	if cached == nil {
		t.Fatalf("DnsGet returned nil for %s", qname)
	}
	if !cached.Zero {
		t.Fatalf("expected cached message to keep Zero set")
	}
	ttl := cached.Answer[0].Header().Ttl
	if ttl > 3 {
		t.Fatalf("ttl was not reduced after cache lookup got=%d", ttl)
	}
	if ttl == 0 {
		t.Fatalf("ttl unexpectedly reached zero after short wait")
	}
}

func newTestMessage(qname string) *dns.Msg {
	return newTestMessageForType(nil, dns.TypeA, qname, 0)
}

func newCacheWithEntries(tb testing.TB, entries int) *Cache {
	tb.Helper()

	cache := NewCache()
	if entries <= 0 {
		return cache
	}

	aCount := min(int(math.Ceil(float64(entries)*0.9)), entries)
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
			cache.DnsSet(newTestMessageForType(tb, qt, qname, entryIdx))
			entryIdx++
		}
	}

	return cache
}

func newTestMessageForType(tb testing.TB, qtype uint16, qname string, idx int) *dns.Msg {
	if tb != nil {
		tb.Helper()
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
		value := uint64(idx) + 1
		addrStr := fmt.Sprintf("2001:db8::%x:%x:%x:%x", (value>>48)&0xffff, (value>>32)&0xffff, (value>>16)&0xffff, value&0xffff)
		addr, addrErr := netip.ParseAddr(addrStr)
		if addrErr == nil {
			addrBytes := addr.As16()
			msg.Answer = []dns.RR{
				&dns.AAAA{
					Hdr:  hdr,
					AAAA: net.IP(addrBytes[:]),
				},
			}
		} else {
			if tb != nil {
				tb.Fatalf("failed to parse ipv6 address for index %d: %v", idx, addrErr)
			}
			panic(fmt.Sprintf("failed to parse ipv6 address for index %d: %v", idx, addrErr))
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
		if tb != nil {
			tb.Fatalf("unsupported qtype %d", qtype)
		}
		panic(fmt.Sprintf("unsupported qtype %d", qtype))
	}

	return msg
}

func TestNewTestMessageForTypeHandlesLargeIndex(t *testing.T) {
	t.Parallel()

	const idx = 1_000_000
	qname := dns.Fqdn("large-index.example.")

	msg := newTestMessageForType(t, dns.TypeAAAA, qname, idx)
	if msg == nil {
		t.Fatalf("newTestMessageForType returned nil for index %d", idx)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}

	aaaa, ok := msg.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("unexpected record type %T", msg.Answer[0])
	}
	if len(msg.Question) == 0 || msg.Question[0].Name != qname {
		t.Fatalf("unexpected question for index %d: %#v", idx, msg.Question)
	}

	parsedAddr := aaaa.AAAA.To16()
	if parsedAddr == nil || len(parsedAddr) != net.IPv6len {
		t.Fatalf("invalid IPv6 address in answer: %v", aaaa.AAAA)
	}

	var addrBytes [net.IPv6len]byte
	copy(addrBytes[:], parsedAddr)
	gotAddr := netip.AddrFrom16(addrBytes)

	expected := [net.IPv6len]byte{0x20, 0x01, 0x0d, 0xb8}
	value := uint64(idx) + 1
	for i := len(expected) - 1; i >= len(expected)-8; i-- {
		expected[i] = byte(value)
		value >>= 8
	}
	expectedAddr := netip.AddrFrom16(expected)

	if gotAddr != expectedAddr {
		t.Fatalf("unexpected IPv6 address for index %d: got %s want %s", idx, gotAddr, expectedAddr)
	}
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

func TestCacheGetAllowsFilteringAndStaleAccess(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	qname := dns.Fqdn("get-allow.example.")
	entryMsg := newTestMessage(qname)
	key := mustBucketKey(t, qname, dns.TypeA)

	freshExpiry := time.Now().Add(45 * time.Second).Unix()
	cache.bucketFor(key).set(entryMsg, freshExpiry)

	allowCalled := false
	got, stale := cache.Get(qname, dns.TypeA, func(msg *dns.Msg, ttl time.Duration) bool {
		allowCalled = true
		return ttl > time.Minute
	})
	if !allowCalled {
		t.Fatalf("allowfn was not invoked for fresh entry")
	}
	if stale {
		t.Fatalf("stale reported true for fresh entry")
	}
	if got != nil {
		t.Fatalf("expected nil message when allowfn rejects entry")
	}
	if entries := cache.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d after rejected entry, want 0", entries)
	}
	if ratio := cache.HitRatio(); ratio != 0 {
		t.Fatalf("HitRatio() = %f after rejected entry, want 0", ratio)
	}

	expiredExpiry := time.Now().Add(-5 * time.Second).Unix()
	cache.bucketFor(key).set(entryMsg, expiredExpiry)

	allowCalled = false
	var observedTTL time.Duration
	got, stale = cache.Get(qname, dns.TypeA, func(msg *dns.Msg, ttl time.Duration) bool {
		allowCalled = true
		observedTTL = ttl
		return true
	})
	if !allowCalled {
		t.Fatalf("allowfn was not invoked for expired entry")
	}
	if got == nil {
		t.Fatalf("expected message when allowfn permits expired entry")
	}
	if !stale {
		t.Fatalf("stale reported false for expired entry")
	}
	if observedTTL >= 0 {
		t.Fatalf("expected negative ttl for expired entry, got %v", observedTTL)
	}
	if entries := cache.Entries(); entries != 1 {
		t.Fatalf("Entries() = %d after expired entry, want 1", entries)
	}
	if ratio := cache.HitRatio(); ratio != 50 {
		t.Fatalf("HitRatio() = %f after expired entry fetch, want 50", ratio)
	}
}

func TestCacheGetAndCleanRemovesExpired(t *testing.T) {
	t.Parallel()

	c := NewCache()
	qname := dns.Fqdn("expired.example")

	msg := newTestMessage(qname)
	key := mustBucketKey(t, qname, dns.TypeA)
	c.bucketFor(key).set(msg, -1)
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
	c.bucketFor(freshKey).set(fresh, -60)
	c.Clean()
	if entries := c.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d after Clean", entries)
	}
}

func TestCacheCleanBeforeUsesProvidedTime(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	qname := dns.Fqdn("clean-before-time.example.")
	key := mustBucketKey(t, qname, dns.TypeA)
	msg := newTestMessage(qname)
	now := time.Now()
	cache.bucketFor(key).set(msg, now.Add(5*time.Minute).Unix())

	if entries := cache.Entries(); entries != 1 {
		t.Fatalf("Entries() = %d before CleanBefore, want 1", entries)
	}

	cache.CleanBefore(now.Add(10 * time.Minute))

	if entries := cache.Entries(); entries != 0 {
		t.Fatalf("Entries() = %d after CleanBefore with future cutoff, want 0", entries)
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
	cqA.set(msgA, expiresA)

	qnameAAAA := dns.Fqdn("walk-aaaa.example")
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(qnameAAAA, dns.TypeAAAA)
	addrAAAA, addrAAAAErr := netip.ParseAddr("2001:db8::5")
	if addrAAAAErr != nil {
		t.Fatalf("failed to parse walk IPv6 address: %v", addrAAAAErr)
	}
	addrAAAABuffer := addrAAAA.As16()
	msgAAAA.Answer = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: qnameAAAA, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.IP(addrAAAABuffer[:]),
		},
	}
	expiresAAAA := now + (10 * 60)
	keyAAAA := mustBucketKey(t, qnameAAAA, dns.TypeAAAA)
	cqAAAA := cache.bucketFor(keyAAAA)
	cqAAAA.set(msgAAAA, expiresAAAA)

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
	cq1.set(msg1, now+60)

	key2 := mustBucketKey(t, qname2, dns.TypeA)
	cq2 := cache.bucketFor(key2)
	cq2.set(msg2, now+(2*60))

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
	wantExpires := int64(time.Now().Unix() + (5 * 60))

	key := mustBucketKey(t, qname, dns.TypeA)
	src.bucketFor(key).set(msg, wantExpires)

	dst.Merge(src)

	cv := mustCacheEntry(t, dst, qname, dns.TypeA, wantExpires)
	if cv.Msg != msg {
		t.Fatalf("merged entry Msg mismatch: got %p want %p", cv.Msg, msg)
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
	shortMsg := newTestMessage(qname)
	dst.bucketFor(key).set(shortMsg, shortExpires)

	longMsg := newTestMessage(qname)
	src.bucketFor(key).set(longMsg, longExpires)

	dst.Merge(src)

	cv := mustCacheEntry(t, dst, qname, dns.TypeA, longExpires)
	if cv.Msg != longMsg {
		t.Fatalf("merge did not replace with longer lived msg")
	}
}

func TestCacheWriteToReadFromRoundTrip(t *testing.T) {
	t.Parallel()

	src := NewCache()
	base := time.Now().Unix()

	qnameA := dns.Fqdn("serialize-a.example.")
	msgA := newTestMessage(qnameA)
	expiresA := base + (5 * 60)
	keyA := mustBucketKey(t, qnameA, dns.TypeA)
	src.bucketFor(keyA).set(msgA, expiresA)

	qnameAAAA := dns.Fqdn("serialize-aaaa.example.")
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(qnameAAAA, dns.TypeAAAA)
	addrAAAA, addrAAAAErr := netip.ParseAddr("2001:db8::10")
	if addrAAAAErr != nil {
		t.Fatalf("failed to parse serialize IPv6 address: %v", addrAAAAErr)
	}
	addrAAAABuffer := addrAAAA.As16()
	msgAAAA.Answer = []dns.RR{
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   qnameAAAA,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			AAAA: net.IP(addrAAAABuffer[:]),
		},
	}
	expiresAAAA := base + (10 * 60)
	keyAAAA := mustBucketKey(t, qnameAAAA, dns.TypeAAAA)
	src.bucketFor(keyAAAA).set(msgAAAA, expiresAAAA)

	buf, written := mustWriteCacheToBuffer(t, src)

	dst := NewCache()
	mustReadCacheFromReader(t, dst, &buf, written)

	mustCacheEntry(t, dst, qnameA, dns.TypeA, expiresA)
	mustCacheEntry(t, dst, qnameAAAA, dns.TypeAAAA, expiresAAAA)
}

func TestCacheWriteToReportsMarshalErrorsButWritesRemaining(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	base := time.Now().Unix()

	goodQname := dns.Fqdn("marshal-good.example")
	goodMsg := newTestMessage(goodQname)
	goodExpires := base + (2 * 60)

	badQname := "marshal-bad.example" // not FQDN to trigger dns.ErrFqdn in MarshalBinary
	badMsg := new(dns.Msg)
	badMsg.SetQuestion(badQname, dns.TypeA)

	goodKey := mustBucketKey(t, goodQname, dns.TypeA)
	cache.bucketFor(goodKey).set(goodMsg, goodExpires)
	badKey := mustBucketKey(t, badQname, dns.TypeA)
	cache.bucketFor(badKey).set(badMsg, base+(5*60))

	var buf bytes.Buffer
	written, err := cache.WriteTo(&buf)
	if err == nil {
		t.Fatalf("WriteTo returned nil error, want marshal failure")
	}
	if !errors.Is(err, dns.ErrFqdn) {
		t.Fatalf("WriteTo error %v, want %v", err, dns.ErrFqdn)
	}
	if written == 0 {
		t.Fatalf("WriteTo wrote zero bytes")
	}

	dst := NewCache()
	mustReadCacheFromReader(t, dst, bytes.NewReader(buf.Bytes()), written)

	mustCacheEntry(t, dst, goodQname, dns.TypeA, goodExpires)
	if entries := dst.Entries(); entries != 1 {
		t.Fatalf("dst cache entries = %d, want 1 (only successfully marshaled entry)", entries)
	}
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
	expiresTXT := time.Now().Unix() + (15 * 60)
	key := mustBucketKey(t, qnameTXT, dns.TypeTXT)
	src.bucketFor(key).set(msgTXT, expiresTXT)

	buf, written := mustWriteCacheToBuffer(t, src)

	dst := NewCache()
	chunked := &chunkedReader{
		r:     bytes.NewReader(buf.Bytes()),
		chunk: chunkSize,
	}
	mustReadCacheFromReader(t, dst, chunked, written)

	mustCacheEntry(t, dst, qnameTXT, dns.TypeTXT, expiresTXT)
}

func TestCacheReadFromRejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	var written int64
	if err := writeInt64(&buf, &written, cacheMagic); err != nil {
		t.Fatalf("writeInt64 returned error: %v", err)
	}

	now := time.Now()

	invalid := cacheValue{Msg: new(dns.Msg), expires: now.Add(time.Hour).Unix()}
	invalidPacked, invalidErr := invalid.MarshalBinary()
	if invalidErr != nil {
		t.Fatalf("MarshalBinary for invalid entry returned error: %v", invalidErr)
	}

	appendCacheBytes := func(data []byte) {
		if len(data) > math.MaxUint16 {
			t.Fatalf("entry too large to encode length: %d bytes", len(data))
		}
		length := uint16(len(data))
		buf.Write([]byte{byte(length >> 8), byte(length)})
		n, _ := buf.Write(data)
		written += int64(n + 2)
	}

	appendCacheBytes(invalidPacked)

	validQname := dns.Fqdn("import-valid.example.")
	valid := cacheValue{
		Msg:     newTestMessage(validQname),
		expires: now.Add(2 * time.Hour).Unix(),
	}
	validPacked, validErr := valid.MarshalBinary()
	if validErr != nil {
		t.Fatalf("MarshalBinary for valid entry returned error: %v", validErr)
	}
	appendCacheBytes(validPacked)

	dst := NewCache()
	read, err := dst.ReadFrom(bytes.NewReader(buf.Bytes()))
	if read != written {
		t.Fatalf("ReadFrom read %d bytes want %d", read, written)
	}
	if !errors.Is(err, ErrInvalidCacheEntry) {
		t.Fatalf("ReadFrom error = %v want ErrInvalidCacheEntry", err)
	}
	if entries := dst.Entries(); entries != 1 {
		t.Fatalf("dst cache entries = %d want 1 (only valid entry)", entries)
	}
	cached := dst.DnsGet(validQname, dns.TypeA)
	if cached == nil {
		t.Fatalf("expected cached entry for %s", validQname)
	}
	if cached.Question[0].Name != validQname {
		t.Fatalf("cached question mismatch got=%s want=%s", cached.Question[0].Name, validQname)
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
		mustReadCacheFromReader(t, dst, readFile, written)
		readFile.Close()

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
		maps.Copy(out, bucket.cache)
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

func mustCacheValue(tb testing.TB, cache *Cache, qname string, qtype uint16) (cv cacheValue) {
	tb.Helper()
	if cache != nil {
		key := newBucketKey(qname, qtype)
		bucket := cache.bucketFor(key)
		bucket.mu.RLock()
		var ok bool
		cv, ok = bucket.cache[key]
		bucket.mu.RUnlock()
		if !ok {
			tb.Fatalf("expected cache entry for %s qtype=%d", qname, qtype)
		}
	} else {
		tb.Fatalf("cache is nil for %s qtype=%d", qname, qtype)
	}
	return
}

func mustCacheEntry(tb testing.TB, cache *Cache, qname string, qtype uint16, wantExpires int64) (cv cacheValue) {
	tb.Helper()
	cv = mustCacheValue(tb, cache, qname, qtype)
	if cv.Msg == nil || len(cv.Msg.Question) == 0 || cv.Msg.Question[0].Name != qname {
		tb.Fatalf("unexpected message for %s: %#v", qname, cv.Msg)
	}
	if cv.Msg.Question[0].Qtype != qtype {
		tb.Fatalf("unexpected qtype for %s: got %d want %d", qname, cv.Msg.Question[0].Qtype, qtype)
	}
	if cv.expires != wantExpires {
		tb.Fatalf("expires mismatch for %s: got %v want %v", qname, cv.expires, wantExpires)
	}
	return
}

func mustWriteCacheToBuffer(tb testing.TB, cache *Cache) (buf bytes.Buffer, written int64) {
	tb.Helper()
	if cache != nil {
		var err error
		if written, err = cache.WriteTo(&buf); err == nil {
			if written <= 0 {
				tb.Fatalf("WriteTo wrote %d bytes", written)
			}
		} else {
			tb.Fatalf("WriteTo returned error: %v", err)
		}
	} else {
		tb.Fatalf("cache is nil")
	}
	return
}

func mustReadCacheFromReader(tb testing.TB, cache *Cache, r io.Reader, expected int64) (read int64) {
	tb.Helper()
	if cache != nil {
		var err error
		if read, err = cache.ReadFrom(r); err == nil {
			if read != expected {
				tb.Fatalf("ReadFrom read %d bytes, want %d", read, expected)
			}
		} else {
			tb.Fatalf("ReadFrom returned error: %v", err)
		}
	} else {
		tb.Fatalf("cache is nil")
	}
	return
}

func assertTTLWithin(tb testing.TB, cv cacheValue, expected, tolerance int64) {
	tb.Helper()
	ttl := int64(time.Until(time.Unix(cv.expires, 0)).Seconds())
	if ttl > expected+tolerance || ttl < expected-tolerance {
		tb.Fatalf("unexpected ttl got=%v want=%v±%v", ttl, expected, tolerance)
	}
}

func TestCacheReadFromFixture(t *testing.T) {
	f, err := os.Open("dnscache.bin")
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	c := NewCache()
	_, err = c.ReadFrom(f)
	if err != nil {
		t.Error(err)
	}
}
