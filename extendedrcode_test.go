package recursive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/miekg/dns"
)

type stubNetError struct {
	timeout   bool
	temporary bool
}

func (e stubNetError) Error() string   { return "stub net error" }
func (e stubNetError) Timeout() bool   { return e.timeout }
func (e stubNetError) Temporary() bool { return e.temporary }

func TestExtendedErrorCodeFromError(t *testing.T) {
	dnsTimeout := &net.DNSError{IsTimeout: true}
	dnsNotFound := &net.DNSError{IsNotFound: true}
	dnsTemporary := &net.DNSError{IsTemporary: true}
	dnsDefault := &net.DNSError{}

	tests := []struct {
		name string
		err  error
		code uint16
	}{
		{"nil error", nil, dns.ExtendedErrorCodeOther},
		{"extended code", extendedErrorCodeError(dns.ExtendedErrorCodeFiltered), dns.ExtendedErrorCodeFiltered},
		{"permission", os.ErrPermission, dns.ExtendedErrorCodeProhibited},
		{"invalid", os.ErrInvalid, dns.ExtendedErrorCodeInvalidData},
		{"path wrapped", &os.PathError{Err: os.ErrPermission}, dns.ExtendedErrorCodeProhibited},
		{"not ready", io.ErrNoProgress, dns.ExtendedErrorCodeNotReady},
		{"network closed", net.ErrClosed, dns.ExtendedErrorCodeNetworkError},
		{"invalid addr", net.InvalidAddrError("bad"), dns.ExtendedErrorCodeInvalidData},
		{"dns timeout", dnsTimeout, dns.ExtendedErrorCodeNoReachableAuthority},
		{"dns not found", dnsNotFound, dns.ExtendedErrorCodeNoReachableAuthority},
		{"dns temporary", dnsTemporary, dns.ExtendedErrorCodeNotReady},
		{"dns default", dnsDefault, dns.ExtendedErrorCodeNetworkError},
		{"io eof", io.EOF, dns.ExtendedErrorCodeOther},
		{"os not exist", os.ErrNotExist, dns.ExtendedErrorCodeNoReachableAuthority},
		{"os exist", os.ErrExist, dns.ExtendedErrorCodeInvalidData},
		{"deadline exceeded", os.ErrDeadlineExceeded, dns.ExtendedErrorCodeNoReachableAuthority},
		{"short buffer", io.ErrShortBuffer, dns.ExtendedErrorCodeInvalidData},
		{"short write", io.ErrShortWrite, dns.ExtendedErrorCodeInvalidData},
		{"closed pipe", io.ErrClosedPipe, dns.ExtendedErrorCodeNetworkError},
		{"unexpected eof", io.ErrUnexpectedEOF, dns.ExtendedErrorCodeInvalidData},
		{"unknown network", net.UnknownNetworkError("bad"), dns.ExtendedErrorCodeNetworkError},
		{"deadline exceeded", context.DeadlineExceeded, dns.ExtendedErrorCodeNoReachableAuthority},
		{"addr error", &net.AddrError{Err: "bad"}, dns.ExtendedErrorCodeInvalidData},
		{"parse error", &net.ParseError{Type: "addr", Text: "bad"}, dns.ExtendedErrorCodeInvalidData},
		{"net timeout interface", stubNetError{timeout: true}, dns.ExtendedErrorCodeNoReachableAuthority},
		{"net default interface", stubNetError{}, dns.ExtendedErrorCodeNetworkError},
		{"net OpError", &net.OpError{}, dns.ExtendedErrorCodeNetworkError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code := ExtendedErrorCodeFromError(tc.err)
			if code != tc.code {
				t.Fatalf("unexpected code %d, want %d", code, tc.code)
			}
		})
	}
}

func TestErrorFromExtendedRcode(t *testing.T) {
	for code, sample := range rcodesToErrors {
		err := ErrorFromExtendedErrorCode(code)
		if !errors.Is(err, sample) {
			t.Fatalf("code %d returned unexpected error %v", code, err)
		}
		if roundTripped := ExtendedErrorCodeFromError(err); roundTripped != code {
			t.Fatalf("code %d did not round trip: got %d", code, roundTripped)
		}
	}
}

func TestErrorFromExtendedErrorCodeUnknown(t *testing.T) {
	code := dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm
	err := ErrorFromExtendedErrorCode(code)

	rcodeErr, ok := err.(extendedErrorCodeError)
	if !ok {
		t.Fatalf("expected extendedRcodeError, got %T", err)
	}
	if rcodeErr != extendedErrorCodeError(code) {
		t.Fatalf("unexpected extended rcode error %v", rcodeErr)
	}
	if !errors.Is(err, ErrExtendedErrorCode) {
		t.Fatalf("extended rcode error should match Err dns.ExtendedErrorCodeError")
	}
	if roundTripped := ExtendedErrorCodeFromError(err); roundTripped != code {
		t.Fatalf("extended rcode error did not round trip: got %d", roundTripped)
	}
}

func TestExtendedErrorCodeErrorMethods(t *testing.T) {
	code := dns.ExtendedErrorCodeCensored
	err := extendedErrorCodeError(code)
	if err.Error() != fmt.Sprintf("extended rcode %d", code) {
		t.Fatalf("unexpected error string %q", err.Error())
	}
	if !errors.Is(err, ErrExtendedErrorCode) {
		t.Fatalf("expected errors.Is to match Err dns.ExtendedErrorCodeError")
	}
	if ExtendedErrorCodeFromError(err) != code {
		t.Fatalf("expected code %d from error", code)
	}
}
