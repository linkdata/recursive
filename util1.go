package recursive

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Enhanced DNS utilities that leverage miekg/dns library functions

// ParseQueryString parses a query string into name and type
func ParseQueryString(query string) (qname string, qtype uint16, err error) {
	parts := strings.Fields(query)
	if len(parts) < 1 {
		return "", 0, fmt.Errorf("invalid query string")
	}

	qname = dns.CanonicalName(parts[0]) // Returns lowercase and FQDN
	qtype = dns.TypeA                   // Default to A record

	if len(parts) > 1 {
		if t, ok := dns.StringToType[strings.ToUpper(parts[1])]; ok {
			qtype = t
		} else {
			return "", 0, fmt.Errorf("unknown query type: %s", parts[1])
		}
	}

	return qname, qtype, nil
}

// CreateStandardQuery creates a standard DNS query message
func CreateStandardQuery(qname string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	msg.RecursionDesired = false // We handle recursion ourselves
	return msg
}

// CreateQueryWithEDNS creates a DNS query with EDNS0 support
func CreateQueryWithEDNS(qname string, qtype uint16, udpSize uint16) *dns.Msg {
	msg := CreateStandardQuery(qname, qtype)

	// Add EDNS0 OPT record using miekg/dns utilities
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(udpSize)

	msg.Extra = append(msg.Extra, opt)
	return msg
}

// ExtractAddressRecords extracts all A and AAAA records from a DNS message
func ExtractAddressRecords(msg *dns.Msg) map[string][]netip.Addr {
	if msg == nil {
		return nil
	}

	addresses := make(map[string][]netip.Addr)

	// Process all sections using miekg/dns record types
	sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}

	for _, section := range sections {
		for _, rr := range section {
			hostname, addr := ExtractHostnameAndAddr(rr)
			if addr.IsValid() {
				addresses[hostname] = append(addresses[hostname], addr)
			}
		}
	}

	return addresses
}

// ExtractNameservers extracts NS records and their glue from a DNS message
func ExtractNameservers(msg *dns.Msg) ([]string, map[string][]netip.Addr) {
	if msg == nil {
		return nil, nil
	}

	var nameservers []string
	glue := make(map[string][]netip.Addr)

	// Extract NS records using miekg/dns type assertions
	sections := [][]dns.RR{msg.Answer, msg.Ns}
	for _, section := range sections {
		for _, rr := range section {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := dns.CanonicalName(ns.Ns)
				nameservers = append(nameservers, nsName)
			}
		}
	}

	// Extract glue records
	glue = ExtractAddressRecords(msg)

	return nameservers, glue
}

// ExtractCNAMETarget extracts the target of a CNAME record if present
func ExtractCNAMETarget(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}

	// Look for CNAME in answer section
	for _, rr := range msg.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			return dns.CanonicalName(cname.Target)
		}
	}

	return ""
}

// IsAuthoritativeAnswer checks if a message represents an authoritative answer
func IsAuthoritativeAnswer(msg *dns.Msg) bool {
	return msg != nil && msg.Authoritative
}

// IsReferralResponse checks if a message is a referral (has NS records but no answers)
func IsReferralResponse(msg *dns.Msg) bool {
	return msg != nil &&
		msg.Rcode == dns.RcodeSuccess &&
		len(msg.Answer) == 0 &&
		len(msg.Ns) > 0
}

// IsTruncatedResponse checks if a response was truncated
func IsTruncatedResponse(msg *dns.Msg) bool {
	return msg != nil && msg.Truncated
}

// GetResponseCode returns the response code as a string
func GetResponseCode(msg *dns.Msg) string {
	if msg == nil {
		return "UNKNOWN"
	}
	return dns.RcodeToString[msg.Rcode]
}

// GetEDNSVersion returns the EDNS version from a message
func GetEDNSVersion(msg *dns.Msg) int {
	if opt := msg.IsEdns0(); opt != nil {
		return int(opt.Version())
	}
	return -1 // No EDNS
}

// GetEDNSUDPSize returns the EDNS UDP size from a message
func GetEDNSUDPSize(msg *dns.Msg) uint16 {
	if opt := msg.IsEdns0(); opt != nil {
		return opt.UDPSize()
	}
	return 0
}

// HasEDNSOption checks if a message has a specific EDNS option
func HasEDNSOption(msg *dns.Msg, optionCode uint16) bool {
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == optionCode {
				return true
			}
		}
	}
	return false
}

// GetDNSCookie extracts DNS cookie from a message
func GetDNSCookie(msg *dns.Msg) string {
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
				return cookie.Cookie
			}
		}
	}
	return ""
}

// SetDNSCookie adds a DNS cookie to a message
func SetDNSCookie(msg *dns.Msg, cookie string) {
	opt := msg.IsEdns0()
	if opt == nil {
		// Add EDNS0 if not present
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(dns.DefaultMsgSize)
		msg.Extra = append(msg.Extra, opt)
	}

	// Remove existing cookie if present
	filteredOptions := make([]dns.EDNS0, 0)
	for _, option := range opt.Option {
		if option.Option() != dns.EDNS0COOKIE {
			filteredOptions = append(filteredOptions, option)
		}
	}

	// Add new cookie
	cookieOption := &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: cookie,
	}
	opt.Option = append(filteredOptions, cookieOption)
}

// ValidateMessage performs basic validation on a DNS message
func ValidateMessage(msg *dns.Msg) error {
	if msg == nil {
		return ErrNilMessage
	}

	if len(msg.Question) == 0 {
		return ErrNoQuestions
	}

	if len(msg.Question) > 1 {
		return ErrMultipleQuestions
	}

	question := msg.Question[0]
	if question.Qclass != dns.ClassINET {
		return newUnsupportedQueryClassError(question.Qclass)
	}

	if !dns.IsFqdn(question.Name) {
		return newInvalidFQDNError(question.Name)
	}

	return nil
}

// CopyMessage creates a deep copy of a DNS message
func CopyMessage(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		return nil
	}
	return msg.Copy() // Use miekg/dns built-in copy method
}

// NormalizeQueryName ensures a query name is in canonical form
func NormalizeQueryName(qname string) string {
	return dns.CanonicalName(dns.Fqdn(qname))
}

// CompareNames compares two DNS names for equality (case-insensitive)
func CompareNames(name1, name2 string) bool {
	return dns.CanonicalName(name1) == dns.CanonicalName(name2)
}

// IsSubdomain checks if child is a subdomain of parent
func IsSubdomain(child, parent string) bool {
	return dns.IsSubDomain(dns.Fqdn(parent), dns.Fqdn(child))
}

// GetLabels returns the labels of a domain name
func GetLabels(name string) []string {
	fqdn := dns.Fqdn(name)
	labels := dns.SplitDomainName(fqdn)
	return labels
}

// GetLabelCount returns the number of labels in a domain name
func GetLabelCount(name string) int {
	return dns.CountLabel(dns.Fqdn(name))
}

// GetParentDomain returns the parent domain of a given domain
func GetParentDomain(name string) string {
	fqdn := dns.Fqdn(name)
	labels := dns.SplitDomainName(fqdn)
	if len(labels) <= 1 {
		return "." // Root domain
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// FormatRecordForLogging formats a DNS record for logging purposes
func FormatRecordForLogging(rr dns.RR) string {
	if rr == nil {
		return "<nil>"
	}

	header := rr.Header()
	recordType := dns.TypeToString[header.Rrtype]

	switch record := rr.(type) {
	case *dns.A:
		return fmt.Sprintf("%s %d IN %s %s",
			header.Name, header.Ttl, recordType, record.A.String())
	case *dns.AAAA:
		return fmt.Sprintf("%s %d IN %s %s",
			header.Name, header.Ttl, recordType, record.AAAA.String())
	case *dns.NS:
		return fmt.Sprintf("%s %d IN %s %s",
			header.Name, header.Ttl, recordType, record.Ns)
	case *dns.CNAME:
		return fmt.Sprintf("%s %d IN %s %s",
			header.Name, header.Ttl, recordType, record.Target)
	default:
		return rr.String() // Use miekg/dns default string representation
	}
}

// GetRecordSummary returns a summary of records in a message
func GetRecordSummary(msg *dns.Msg) string {
	if msg == nil {
		return "nil message"
	}

	return fmt.Sprintf("[%d+%d+%d A/N/E]",
		len(msg.Answer), len(msg.Ns), len(msg.Extra))
}
