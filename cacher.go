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

// DelegationCacheProvider permits direct cache reads for internal delegation lookups.
//
// When DelegationCache returns a non-nil cache, that [Cacher]'s DnsGet must have
// the same response contents, eligibility, expiration and filtering rules as
// [Cache.DnsGet], with no required per-read side effects. Resolution may bypass
// the Cacher's DnsGet for these reads. Successful replies are immutable and their
// record TTLs need not be capped at the remaining cache lifetime. Other replies
// retain [Cache.DnsGet]'s TTL rules. Final-response lookups and cache writes still
// use the Cacher.
//
// DelegationCache may return nil to use the Cacher's DnsGet. Implementations
// must support concurrent calls.
type DelegationCacheProvider interface {
	// DelegationCache returns the cache to read directly, or nil to use DnsGet.
	DelegationCache() *Cache
}
