package recursive

import (
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// DNS and networking constants
const (
	// Protocol and connection constants
	DefaultDNSPort = 53
	
	// Query limits and timeouts
	MaxRecursionDepth     = 32
	MaxQuerySteps         = 1000
	MaxCNAMEChainLength   = 10
	DefaultQueryTimeout   = 5000 // milliseconds
	
	// Cache configuration
	DefaultCacheMinTTL    = 10   // seconds
	DefaultCacheMaxTTL    = 3600 // seconds  
	DefaultCacheNXTTL     = 3600 // seconds
	MaxCacheQTypes        = 260
	MaxCacheEntriesPerType = 10000
	
	// Network error handling
	NetworkErrorRetentionTime = 60 // seconds
	MaxNetworkErrorsTracked   = 1000
	
	// DNS cookie management
	MaxServerCookies     = 8192
	ServerCookieTTLHours = 24
	ClientCookieLength   = 16 // hex characters
	
	// Root server management
	RootServerTestProbes = 3
	MaxRootServerLatency = 60000 // milliseconds
	
	// Query type string mappings
	UnknownQTypePrefix = "TYPE"
)

// Error message templates
const (
	ErrMsgInvalidCookie    = "DNS cookie validation failed"
	ErrMsgMaxDepthExceeded = "maximum recursion depth of %d exceeded"
	ErrMsgMaxStepsExceeded = "maximum query steps of %d exceeded"  
	ErrMsgNoResponse       = "no authoritative servers responded"
	ErrMsgQuestionMismatch = "response question does not match query"
	ErrMsgNoUsableServers  = "no usable DNS servers available"
	ErrMsgNetworkDisabled  = "network protocol is disabled"
)

// Utility functions for DNS operations

// DnsTypeToString converts a DNS record type number to its string representation
func DnsTypeToString(qtype uint16) string {
	if typeName, exists := dns.TypeToString[qtype]; exists {
		return true
}

// isValidLabel checks if a domain name label is valid according to DNS rules
func isValidLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	
	// Label cannot start or end with hyphen
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	
	// Label can only contain letters, digits, and hyphens
	for _, char := range label {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-') {
			return false
		}
	}
	
	return true
}

// MaskCookie masks a DNS cookie string for logging privacy
func MaskCookie(cookie string) string {
	const visibleChars = 8
	if len(cookie) <= visibleChars {
		return cookie
	}
	return cookie[:visibleChars] + "..."
}

// FormatDuration formats a duration for human-readable logging
func FormatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%.0fns", float64(d))
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fμs", float64(d)/float64(time.Microsecond))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// ExtractHostnameAndAddr extracts hostname and IP address from a DNS resource record
func ExtractHostnameAndAddr(rr dns.RR) (hostname string, addr netip.Addr) {
	switch record := rr.(type) {
	case *dns.A:
		if ip, ok := netip.AddrFromSlice(record.A); ok {
			hostname = dns.CanonicalName(record.Hdr.Name)
			addr = ip.Unmap()
		}
	case *dns.AAAA:
		if ip, ok := netip.AddrFromSlice(record.AAAA); ok {
			hostname = dns.CanonicalName(record.Hdr.Name)
			addr = ip
		}
	}
	return hostname, addr
}

// CreateErrorResponse creates a DNS error response message
func CreateErrorResponse(qname string, qtype uint16, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Rcode = rcode
	return msg
}

// IsAuthoritativeResponse checks if a DNS message represents an authoritative response
func IsAuthoritativeResponse(msg *dns.Msg) bool {
	return msg != nil && msg.Authoritative
}

// HasAnswerRecords checks if a DNS message has answer records
func HasAnswerRecords(msg *dns.Msg) bool {
	return msg != nil && len(msg.Answer) > 0
}

// HasNameserverRecords checks if a DNS message has nameserver records
func HasNameserverRecords(msg *dns.Msg) bool {
	return msg != nil && len(msg.Ns) > 0
}

// IsSuccessfulResponse checks if a DNS response indicates success
func IsSuccessfulResponse(msg *dns.Msg) bool {
	return msg != nil && msg.Rcode == dns.RcodeSuccess
}

// IsTemporaryError checks if a DNS response represents a temporary error
func IsTemporaryError(msg *dns.Msg) bool {
	if msg == nil {
		return true // No response is considered temporary
	}
	return msg.Rcode == dns.RcodeServerFailure
}

// ShouldCacheResponse determines if a DNS response should be cached
func ShouldCacheResponse(msg *dns.Msg) bool {
	if msg == nil || msg.Zero {
		return false // Don't cache nil or already cached responses
	}
	
	// Cache successful responses
	if msg.Rcode == dns.RcodeSuccess {
		return true
	}
	
	// Cache NXDOMAIN responses
	if msg.Rcode == dns.RcodeNameError {
		return true
	}
	
	// Cache other definitive errors
	switch msg.Rcode {
	case dns.RcodeNotImplemented, dns.RcodeRefused:
		return true
	}
	
	return false
}

// GetMessageSize calculates the size of a DNS message in bytes
func GetMessageSize(msg *dns.Msg) int {
	if msg == nil {
		return 0
	}
	return msg.Len()
}

// Network utility functions

// IsIPv4Address checks if an address is IPv4
func IsIPv4Address(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is4()
}

// IsIPv6Address checks if an address is IPv6  
func IsIPv6Address(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is6()
}

// IsLoopbackAddress checks if an address is a loopback address
func IsLoopbackAddress(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsLoopback()
}

// IsPrivateAddress checks if an address is in private address space
func IsPrivateAddress(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsPrivate()
}

// FormatAddressPort formats an address and port for connection strings
func FormatAddressPort(addr netip.Addr, port uint16) string {
	return netip.AddrPortFrom(addr, port).String()
}

// Validation helper functions

// IsValidQueryType checks if a query type is valid and supported
func IsValidQueryType(qtype uint16) bool {
	return qtype > 0 && qtype <= MaxCacheQTypes
}

// IsValidTTL checks if a TTL value is reasonable
func IsValidTTL(ttl uint32) bool {
	// TTL should be non-zero and not unreasonably large (1 year max)
	return ttl > 0 && ttl <= 365*24*3600
}

// IsValidMessageID checks if a DNS message ID is valid
func IsValidMessageID(id uint16) bool {
	return true // All 16-bit values are valid message IDs
}

// String formatting utilities

// TruncateString truncates a string to a maximum length with ellipsis
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// FormatByteCount formats a byte count in human-readable form
func FormatByteCount(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
} typeName
	}
	return UnknownQTypePrefix + strconv.FormatUint(uint64(qtype), 10)
}

// AddrFromRR extracts an IP address from a DNS resource record
func AddrFromRR(rr dns.RR) netip.Addr {
	switch record := rr.(type) {
	case *dns.A:
		if addr, ok := netip.AddrFromSlice(record.A); ok {
			return addr.Unmap() // Ensure IPv4 addresses are not mapped
		}
	case *dns.AAAA:
		if addr, ok := netip.AddrFromSlice(record.AAAA); ok {
			return addr
		}
	}
	return netip.Addr{} // Return zero value for invalid address
}

// MinTTL finds the minimum TTL value among all resource records in a DNS message
// Returns -1 if no records are found (excluding OPT records)
func MinTTL(msg *dns.Msg) int {
	if msg == nil {
		return -1
	}
	
	minTTL := math.MaxInt32
	recordCount := 0
	
	// Check all record sections
	recordSections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}
	
	for _, section := range recordSections {
		for _, rr := range section {
			header := rr.Header()
			// Skip OPT pseudo-records as they don't have meaningful TTL values
			if header.Rrtype != dns.TypeOPT {
				ttl := int(header.Ttl)
				if ttl < minTTL {
					minTTL = ttl
				}
				recordCount++
			}
		}
	}
	
	if recordCount == 0 {
		return -1 // No records found
	}
	
	return minTTL
}

// IsValidDomainName checks if a string is a valid domain name
func IsValidDomainName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	
	// Domain names should end with a dot in DNS contexts
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) == 0 {
		return false
	}
	
	for _, label := range labels {
		if !isValidLabel(label) {
			return false
		}
	}
	
	return