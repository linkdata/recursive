package recursive

import (
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
