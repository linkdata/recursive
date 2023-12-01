package recursive

import (
	"net/netip"

	"github.com/miekg/dns"
)

type Cacher interface {
	DnsSet(nsaddr netip.Addr, msg *dns.Msg)
	DnsGet(nsaddr netip.Addr, qname string, qtype uint16) (netip.Addr, *dns.Msg)
}
