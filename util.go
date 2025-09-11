package recursive

import (
	"math"
	"net/netip"
	"strconv"

	"github.com/miekg/dns"
)

// DnsTypeToString converts a DNS type to its string representation
func DnsTypeToString(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return strconv.Itoa(int(qtype))
}

// AddrFromRR extracts an IP address from a DNS resource record
func AddrFromRR(rr dns.RR) netip.Addr {
	switch v := rr.(type) {
	case *dns.A:
		if ip, ok := netip.AddrFromSlice(v.A); ok {
			return ip.Unmap()
		}
	case *dns.AAAA:
		if ip, ok := netip.AddrFromSlice(v.AAAA); ok {
			return ip
		}
	}
	return netip.Addr{}
}

// MinTTL returns the lowest resource record TTL in the message, or -1 if there are no records.
func MinTTL(msg *dns.Msg) int {
	minTTL := math.MaxInt

	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			// Skip OPT records as they don't have meaningful TTLs
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			ttl := int(rr.Header().Ttl)
			if ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if minTTL == math.MaxInt {
		return -1
	}

	return minTTL
}
