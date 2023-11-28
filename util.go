package recursive

import (
	"math"
	"net/netip"
	"strconv"

	"github.com/miekg/dns"
)

func DnsTypeToString(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return strconv.Itoa(int(qtype))
}

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
	for _, rr := range msg.Answer {
		minTTL = min(minTTL, int(rr.Header().Ttl))
	}
	for _, rr := range msg.Ns {
		minTTL = min(minTTL, int(rr.Header().Ttl))
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			minTTL = min(minTTL, int(rr.Header().Ttl))
		}
	}
	if minTTL == math.MaxInt {
		minTTL = -1
	}
	return minTTL
}
