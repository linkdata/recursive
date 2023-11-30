package recursive

import (
	"net/netip"

	"github.com/miekg/dns"
)

type Cacher interface {
	Get(nsaddr netip.Addr, qname string, qtype uint16) *dns.Msg
	Set(nsaddr netip.Addr, msg *dns.Msg)
}
