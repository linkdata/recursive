package recursive

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

// Resolver performs recursive DNS resolution
type Resolver interface {
	DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error)
}

// Cacher provides DNS response caching
type Cacher interface {
	// DnsSet may make a copy of msg and set its dns.Msg.Zero to true and return it later with DnsGet.
	DnsSet(msg *dns.Msg)

	// DnsGet returns the cached dns.Msg for the given qname and qtype, or nil.
	// Do not modify the returned msg. Make a copy of it if needed.
	//
	// dns.Msg.Zero must be set to true to indicate response is served from cache.
	DnsGet(qname string, qtype uint16) *dns.Msg
}

// CachingResolver combines Resolver and Cacher interfaces
type CachingResolver interface {
	Resolver
	Cacher
}
