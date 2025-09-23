package recursive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/miekg/dns"
)

// ExtendedRcode represents a DNS Extended Error code as defined in RFC 8914.

type extendedErrorCodeError uint16

func (e extendedErrorCodeError) Error() string {
	return fmt.Sprintf("extended rcode %v", uint16(e))
}

func (e extendedErrorCodeError) Is(err error) bool {
	return err == ErrExtendedErrorCode
}

var ErrExtendedErrorCode = extendedErrorCodeError(0)

var rcodesToErrors = map[uint16]error{
	dns.ExtendedErrorCodeOther:                io.EOF,
	dns.ExtendedErrorCodeNotReady:             io.ErrNoProgress,
	dns.ExtendedErrorCodeProhibited:           os.ErrPermission,
	dns.ExtendedErrorCodeNoReachableAuthority: os.ErrDeadlineExceeded,
	dns.ExtendedErrorCodeNetworkError:         net.ErrClosed,
	dns.ExtendedErrorCodeInvalidData:          os.ErrInvalid,
}

// ExtendedErrorCodeFromError attempts to map a Go error to a DNS Extended Rcode.
// The function understands well-known errors from the os, io, and net packages
// (including their wrapper types) and returns dns.ExtendedErrorCodeOther if no mapping is known.
func ExtendedErrorCodeFromError(err error) (rcode uint16) {
	rcode = dns.ExtendedErrorCodeOther
	if err != nil {
		if rcodeErr, ok := err.(extendedErrorCodeError); ok {
			return uint16(rcodeErr)
		}

		for code, sample := range rcodesToErrors {
			if errors.Is(err, sample) {
				return code
			}
		}

		if errors.Is(err, os.ErrNotExist) {
			return dns.ExtendedErrorCodeNoReachableAuthority
		}
		if errors.Is(err, os.ErrExist) {
			return dns.ExtendedErrorCodeInvalidData
		}
		if errors.Is(err, os.ErrDeadlineExceeded) ||
			errors.Is(err, context.DeadlineExceeded) {
			return dns.ExtendedErrorCodeNoReachableAuthority
		}

		if errors.Is(err, io.ErrShortBuffer) || errors.Is(err, io.ErrShortWrite) {
			return dns.ExtendedErrorCodeInvalidData
		}
		if errors.Is(err, io.ErrClosedPipe) {
			return dns.ExtendedErrorCodeNetworkError
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return dns.ExtendedErrorCodeInvalidData
		}

		var unknownNet net.UnknownNetworkError
		if errors.As(err, &unknownNet) {
			return dns.ExtendedErrorCodeNetworkError
		}
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) {
			return dns.ExtendedErrorCodeInvalidData
		}
		var invalidAddr net.InvalidAddrError
		if errors.As(err, &invalidAddr) {
			return dns.ExtendedErrorCodeInvalidData
		}
		var parseErr *net.ParseError
		if errors.As(err, &parseErr) {
			return dns.ExtendedErrorCodeInvalidData
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsTimeout, dnsErr.IsNotFound:
				return dns.ExtendedErrorCodeNoReachableAuthority
			case dnsErr.IsTemporary:
				return dns.ExtendedErrorCodeNotReady
			default:
				return dns.ExtendedErrorCodeNetworkError
			}
		}

		var netErr net.Error
		if errors.As(err, &netErr) {
			switch {
			case netErr.Timeout():
				return dns.ExtendedErrorCodeNoReachableAuthority
			default:
				return dns.ExtendedErrorCodeNetworkError
			}
		}
	}
	return
}

// ErrorFromExtendedErrorCode returns the canonical Go error for the provided
// Extended Error Code. It returns ErrExtendedErrorCode if there is no known mapping.
func ErrorFromExtendedErrorCode(code uint16) (err error) {
	var ok bool
	if err, ok = rcodesToErrors[code]; !ok {
		err = extendedErrorCodeError(code)
	}
	return
}
