package recursive

import (
	"github.com/miekg/dns"
)

type Cacher interface {
	// DnsSet may store a copy of msg with dns.Msg.Zero set to true and return it later with DnsGet.
	// If nsaddr is invalid, the entry may be returned for any later query matching just the
	// query name and type (a wildcard entry).
	DnsSet(msg *dns.Msg)

	// DnsGet returns the cached dns.Msg for the given qname and qtype that was returned from the
	// server at nsaddr. If that is not in the cache, a wildcard entry with an invalid address
	// may be returned if it exists. If no matching responses are available, nil is returned.
	//
	// dns.Msg.Zero must be set to true to indicate response is served from cache.
	DnsGet(qname string, qtype uint16) *dns.Msg
}
