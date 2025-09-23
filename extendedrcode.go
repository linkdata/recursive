package recursive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// ExtendedRcode represents a DNS Extended Error code as defined in RFC 8914.
type ExtendedRcode uint16

const (
	ExtendedRcodeOther                      ExtendedRcode = 0
	ExtendedRcodeUnsupportedDNSKEYAlgorithm ExtendedRcode = 1
	ExtendedRcodeUnsupportedDSDigestType    ExtendedRcode = 2
	ExtendedRcodeStaleAnswer                ExtendedRcode = 3
	ExtendedRcodeForgedAnswer               ExtendedRcode = 4
	ExtendedRcodeDNSSECIndeterminate        ExtendedRcode = 5
	ExtendedRcodeDNSSECBogus                ExtendedRcode = 6
	ExtendedRcodeSignatureExpired           ExtendedRcode = 7
	ExtendedRcodeSignatureNotYetValid       ExtendedRcode = 8
	ExtendedRcodeDNSKEYMissing              ExtendedRcode = 9
	ExtendedRcodeRRSIGsMissing              ExtendedRcode = 10
	ExtendedRcodeNoZoneKeyBitSet            ExtendedRcode = 11
	ExtendedRcodeNSECMissing                ExtendedRcode = 12
	ExtendedRcodeCachedError                ExtendedRcode = 13
	ExtendedRcodeNotReady                   ExtendedRcode = 14
	ExtendedRcodeBlocked                    ExtendedRcode = 15
	ExtendedRcodeCensored                   ExtendedRcode = 16
	ExtendedRcodeFiltered                   ExtendedRcode = 17
	ExtendedRcodeProhibited                 ExtendedRcode = 18
	ExtendedRcodeStaleNXDomainAnswer        ExtendedRcode = 19
	ExtendedRcodeNotAuthoritative           ExtendedRcode = 20
	ExtendedRcodeNotSupported               ExtendedRcode = 21
	ExtendedRcodeNoReachableAuthority       ExtendedRcode = 22
	ExtendedRcodeNetworkError               ExtendedRcode = 23
	ExtendedRcodeInvalidData                ExtendedRcode = 24
)

type extendedRcodeError ExtendedRcode

func (e extendedRcodeError) Error() string {
	return fmt.Sprintf("extended rcode %v", uint16(e))
}

func (e extendedRcodeError) Is(err error) bool {
	return err == ErrExtendedRcode
}

var ErrExtendedRcode = extendedRcodeError(0)

var rcodesToErrors = map[ExtendedRcode]error{
	ExtendedRcodeOther:                io.EOF,
	ExtendedRcodeNotReady:             io.ErrNoProgress,
	ExtendedRcodeProhibited:           os.ErrPermission,
	ExtendedRcodeNoReachableAuthority: os.ErrDeadlineExceeded,
	ExtendedRcodeNetworkError:         net.ErrClosed,
	ExtendedRcodeInvalidData:          os.ErrInvalid,
}

// ExtendedRcodeFromError attempts to map a Go error to a DNS Extended Rcode.
// The function understands well-known errors from the os, io, and net packages
// (including their wrapper types) and returns ExtendedRcodeOther if no mapping is known.
func ExtendedRcodeFromError(err error) (rcode ExtendedRcode) {
	if err != nil {
		if rcodeErr, ok := err.(extendedRcodeError); ok {
			return ExtendedRcode(rcodeErr)
		}

		for code, sample := range rcodesToErrors {
			if errors.Is(err, sample) {
				return code
			}
		}

		if errors.Is(err, os.ErrNotExist) {
			return ExtendedRcodeNoReachableAuthority
		}
		if errors.Is(err, os.ErrExist) {
			return ExtendedRcodeInvalidData
		}
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return ExtendedRcodeNoReachableAuthority
		}

		if errors.Is(err, io.ErrShortBuffer) || errors.Is(err, io.ErrShortWrite) {
			return ExtendedRcodeInvalidData
		}
		if errors.Is(err, io.ErrClosedPipe) {
			return ExtendedRcodeNetworkError
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return ExtendedRcodeInvalidData
		}

		var unknownNet net.UnknownNetworkError
		if errors.As(err, &unknownNet) {
			return ExtendedRcodeNetworkError
		}
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) {
			return ExtendedRcodeInvalidData
		}
		var invalidAddr net.InvalidAddrError
		if errors.As(err, &invalidAddr) {
			return ExtendedRcodeInvalidData
		}
		var parseErr *net.ParseError
		if errors.As(err, &parseErr) {
			return ExtendedRcodeInvalidData
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsTimeout, dnsErr.IsNotFound:
				return ExtendedRcodeNoReachableAuthority
			case dnsErr.IsTemporary:
				return ExtendedRcodeNotReady
			default:
				return ExtendedRcodeNetworkError
			}
		}

		var netErr net.Error
		if errors.As(err, &netErr) {
			switch {
			case netErr.Timeout():
				return ExtendedRcodeNoReachableAuthority
			default:
				return ExtendedRcodeNetworkError
			}
		}
	}
	return
}

// ErrorFromExtendedRcode returns the canonical Go error for the provided
// Extended Rcode. It returns ErrExtendedRcode if there is no known mapping.
func ErrorFromExtendedRcode(code ExtendedRcode) (err error) {
	var ok bool
	if err, ok = rcodesToErrors[code]; !ok {
		err = extendedRcodeError(code)
	}
	return
}
