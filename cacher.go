package recursive

import (
	"net/netip"

	"github.com/miekg/dns"
)

type Cacher interface {
	// DnsSet may store a copy of msg with dns.Msg.Zero set to true and return it later with DnsGet.
	DnsSet(nsaddr netip.Addr, msg *dns.Msg)

	// DnsGet returns the cached dns.Msg for the given qname and qtype. If nsaddr is valid, only cached responses
	// from that server are returned. dns.Msg.Zero must be set to true to indicate response is served from cache.
	DnsGet(nsaddr netip.Addr, qname string, qtype uint16) (netip.Addr, *dns.Msg)
}
