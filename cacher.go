package recursive

import (
	"github.com/miekg/dns"
)

type Cacher interface {
	// DnsSet stores msg for the supplied question. Implementations may keep a
	// private copy, but the cached instance must have dns.Msg.Zero set to true
	// before it is returned by DnsGet.
	DnsSet(msg *dns.Msg)

	// DnsGet returns the cached dns.Msg pointer for the given qname and qtype, or
	// nil if no entry exists. The returned message MUST keep dns.Msg.Zero set to
	// true to signal it originated from cache, and callers MUST treat it as
	// immutable by copying it before applying any mutations.
	DnsGet(qname string, qtype uint16) *dns.Msg
}
