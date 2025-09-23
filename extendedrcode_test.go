package recursive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

type stubNetError struct {
	timeout   bool
	temporary bool
}

func (e stubNetError) Error() string   { return "stub net error" }
func (e stubNetError) Timeout() bool   { return e.timeout }
func (e stubNetError) Temporary() bool { return e.temporary }

func TestExtendedRcodeFromError(t *testing.T) {
	dnsTimeout := &net.DNSError{IsTimeout: true}
	dnsNotFound := &net.DNSError{IsNotFound: true}
	dnsTemporary := &net.DNSError{IsTemporary: true}
	dnsDefault := &net.DNSError{}

	tests := []struct {
		name string
		err  error
		code ExtendedRcode
	}{
		{"nil error", nil, ExtendedRcodeOther},
		{"extended code", extendedRcodeError(ExtendedRcodeFiltered), ExtendedRcodeFiltered},
		{"permission", os.ErrPermission, ExtendedRcodeProhibited},
		{"invalid", os.ErrInvalid, ExtendedRcodeInvalidData},
		{"path wrapped", &os.PathError{Err: os.ErrPermission}, ExtendedRcodeProhibited},
		{"not ready", io.ErrNoProgress, ExtendedRcodeNotReady},
		{"network closed", net.ErrClosed, ExtendedRcodeNetworkError},
		{"invalid addr", net.InvalidAddrError("bad"), ExtendedRcodeInvalidData},
		{"dns timeout", dnsTimeout, ExtendedRcodeNoReachableAuthority},
		{"dns not found", dnsNotFound, ExtendedRcodeNoReachableAuthority},
		{"dns temporary", dnsTemporary, ExtendedRcodeNotReady},
		{"dns default", dnsDefault, ExtendedRcodeNetworkError},
		{"io eof", io.EOF, ExtendedRcodeOther},
		{"os not exist", os.ErrNotExist, ExtendedRcodeNoReachableAuthority},
		{"os exist", os.ErrExist, ExtendedRcodeInvalidData},
		{"deadline exceeded", os.ErrDeadlineExceeded, ExtendedRcodeNoReachableAuthority},
		{"short buffer", io.ErrShortBuffer, ExtendedRcodeInvalidData},
		{"short write", io.ErrShortWrite, ExtendedRcodeInvalidData},
		{"closed pipe", io.ErrClosedPipe, ExtendedRcodeNetworkError},
		{"unexpected eof", io.ErrUnexpectedEOF, ExtendedRcodeInvalidData},
		{"unknown network", net.UnknownNetworkError("bad"), ExtendedRcodeNetworkError},
		{"deadline exceeded", context.DeadlineExceeded, ExtendedRcodeNoReachableAuthority},
		{"addr error", &net.AddrError{Err: "bad"}, ExtendedRcodeInvalidData},
		{"parse error", &net.ParseError{Type: "addr", Text: "bad"}, ExtendedRcodeInvalidData},
		{"net timeout interface", stubNetError{timeout: true}, ExtendedRcodeNoReachableAuthority},
		{"net default interface", stubNetError{}, ExtendedRcodeNetworkError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code := ExtendedRcodeFromError(tc.err)
			if code != tc.code {
				t.Fatalf("unexpected code %d, want %d", code, tc.code)
			}
		})
	}
}

func TestErrorFromExtendedRcode(t *testing.T) {
	for code, sample := range rcodesToErrors {
		err := ErrorFromExtendedRcode(code)
		if !errors.Is(err, sample) {
			t.Fatalf("code %d returned unexpected error %v", code, err)
		}
		if roundTripped := ExtendedRcodeFromError(err); roundTripped != code {
			t.Fatalf("code %d did not round trip: got %d", code, roundTripped)
		}
	}
}

func TestErrorFromExtendedRcodeUnknown(t *testing.T) {
	code := ExtendedRcodeUnsupportedDNSKEYAlgorithm
	err := ErrorFromExtendedRcode(code)

	rcodeErr, ok := err.(extendedRcodeError)
	if !ok {
		t.Fatalf("expected extendedRcodeError, got %T", err)
	}
	if rcodeErr != extendedRcodeError(code) {
		t.Fatalf("unexpected extended rcode error %v", rcodeErr)
	}
	if !errors.Is(err, ErrExtendedRcode) {
		t.Fatalf("extended rcode error should match ErrExtendedRcodeError")
	}
	if roundTripped := ExtendedRcodeFromError(err); roundTripped != code {
		t.Fatalf("extended rcode error did not round trip: got %d", roundTripped)
	}
}

func TestExtendedRcodeErrorMethods(t *testing.T) {
	code := ExtendedRcodeCensored
	err := extendedRcodeError(code)
	if err.Error() != fmt.Sprintf("extended rcode %d", code) {
		t.Fatalf("unexpected error string %q", err.Error())
	}
	if !errors.Is(err, ErrExtendedRcode) {
		t.Fatalf("expected errors.Is to match ErrExtendedRcodeError")
	}
	if ExtendedRcodeFromError(err) != code {
		t.Fatalf("expected code %d from error", code)
	}
}
