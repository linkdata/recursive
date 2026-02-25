package recursive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMismatchedQuestionErrorIs(t *testing.T) {
	t.Parallel()

	err := &MismatchedQuestionError{
		ExpectedQName: dns.Fqdn("legit.example"),
		ExpectedQType: dns.TypeA,
		ActualQName:   dns.Fqdn("poisoned.example"),
		ActualQType:   dns.TypeAAAA,
	}

	if !errors.Is(err, ErrMismatchedQuestion) {
		t.Fatalf("expected errors.Is to match ErrMismatchedQuestion, got %v", err)
	}
}

func TestMismatchedQuestionErrorError(t *testing.T) {
	t.Parallel()

	err := &MismatchedQuestionError{
		ExpectedQName: dns.Fqdn("legit.example"),
		ExpectedQType: dns.TypeA,
		ActualQName:   dns.Fqdn("poisoned.example"),
		ActualQType:   dns.TypeAAAA,
	}

	msg := err.Error()
	if !strings.Contains(msg, `expected="legit.example."/A`) {
		t.Fatalf("error message missing expected section: %q", msg)
	}
	if !strings.Contains(msg, `actual="poisoned.example."/AAAA`) {
		t.Fatalf("error message missing actual section: %q", msg)
	}
}

func TestExchangeRejectsMismatchedResponseQuestion(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if closeErr := serverConn.Close(); closeErr != nil {
				t.Errorf("close server connection: %v", closeErr)
			}
		}()
		var lenbuf [2]byte
		if _, readErr := io.ReadFull(serverConn, lenbuf[:]); readErr == nil {
			msgLen := int(binary.BigEndian.Uint16(lenbuf[:]))
			buf := make([]byte, msgLen)
			if _, readErr = io.ReadFull(serverConn, buf); readErr == nil {
				var req dns.Msg
				if unpackErr := req.Unpack(buf); unpackErr == nil {
					resp := new(dns.Msg)
					resp.SetQuestion(dns.Fqdn("poisoned.example."), dns.TypeA)
					resp.Id = req.Id
					resp.Response = true
					resp.Authoritative = true
					resp.Answer = []dns.RR{
						&dns.A{
							Hdr: dns.RR_Header{
								Name:   dns.Fqdn("poisoned.example."),
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.IPv4(203, 0, 113, 10),
						},
					}
					if packed, packErr := resp.Pack(); packErr == nil {
						var out bytes.Buffer
						_ = binary.Write(&out, binary.BigEndian, uint16(len(packed)))
						out.Write(packed)
						_, _ = serverConn.Write(out.Bytes())
					}
				}
			}
		}
	}()

	cache := NewCache()
	cache.MinTTL = 0
	rec := NewWithOptions(&singleUseDialer{conn: clientConn}, cache, nil, nil, nil)
	rec.DNSPort = 0
	q := &query{Recursive: rec, cache: cache, start: time.Now()}
	qname := dns.Fqdn("legit.example.")

	msg, err := q.exchangeWithNetwork(context.Background(), "tcp", qname, dns.TypeA, netip.MustParseAddr("127.0.0.1"))
	<-done

	if !errors.Is(err, ErrMismatchedQuestion) {
		t.Fatalf("expected ErrMismatchedQuestion, got %v", err)
	}
	var mismatchedErr *MismatchedQuestionError
	if !errors.As(err, &mismatchedErr) {
		t.Fatalf("expected *MismatchedQuestionError, got %T", err)
	}
	if mismatchedErr.ExpectedQName != dns.CanonicalName(qname) {
		t.Fatalf("unexpected expected qname got=%q want=%q", mismatchedErr.ExpectedQName, dns.CanonicalName(qname))
	}
	if mismatchedErr.ExpectedQType != dns.TypeA {
		t.Fatalf("unexpected expected qtype got=%s want=%s", dns.Type(mismatchedErr.ExpectedQType), dns.Type(dns.TypeA))
	}
	if mismatchedErr.ActualQName != dns.Fqdn("poisoned.example.") {
		t.Fatalf("unexpected actual qname got=%q want=%q", mismatchedErr.ActualQName, dns.Fqdn("poisoned.example."))
	}
	if mismatchedErr.ActualQType != dns.TypeA {
		t.Fatalf("unexpected actual qtype got=%s want=%s", dns.Type(mismatchedErr.ActualQType), dns.Type(dns.TypeA))
	}
	if msg != nil {
		t.Fatalf("expected no message on mismatched question, got %v", msg)
	}
	if poisoned := cache.DnsGet(dns.Fqdn("poisoned.example."), dns.TypeA); poisoned != nil {
		t.Fatalf("poisoned response was cached: %v", poisoned)
	}
}

type singleUseDialer struct {
	conn net.Conn
}

func (d *singleUseDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *singleUseDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	if d.conn == nil {
		return nil, errors.New("no connection available")
	}
	conn := d.conn
	d.conn = nil
	return conn, nil
}
