package recursive

import (
	"github.com/miekg/dns"
)

type Cacher interface {
	// DnsSet may make a copy of msg and set its dns.Msg.Zero to true and return it later with DnsGet.
	DnsSet(msg *dns.Msg)

	// DnsGet returns the cached dns.Msg for the given qname and qtype, or nil.
	// Do not modify the returned msg. Make a copy of it if needed.
	//
	// dns.Msg.Zero must be set to true to indicate response is served from cache.
	DnsGet(qname string, qtype uint16) *dns.Msg
}
