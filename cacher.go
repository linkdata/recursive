package recursive

import (
	"github.com/miekg/dns"
)

type Cacher interface {
	// DnsSet may store a copy of msg with dns.Msg.Zero set to true and return it later with DnsGet.
	DnsSet(msg *dns.Msg)

	// DnsGet returns the cached dns.Msg for the given qname and qtype, or nil.
	//
	// dns.Msg.Zero must be set to true to indicate response is served from cache.
	DnsGet(qname string, qtype uint16) *dns.Msg
}
