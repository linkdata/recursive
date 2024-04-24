package recursive

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type CachedResolver struct {
	proxy.ContextDialer
	*Recursive
	Cacher
}

var DefaultCachedResolver = NewCachedResolver(nil, nil, nil)

func NewCachedResolver(rec *Recursive, cd proxy.ContextDialer, cacher Cacher) CachingResolver {
	if rec == nil {
		rec = New()
	}
	if cd == nil {
		cd = &defaultNetDialer
	}
	if cacher == nil {
		cacher = DefaultCache
	}
	return &CachedResolver{
		ContextDialer: cd,
		Recursive:     rec,
		Cacher:        cacher,
	}
}

func (std *CachedResolver) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return std.Recursive.ResolveWithOptions(ctx, std, std, nil, qname, qtype)
}

/*LookupHost(ctx context.Context, host string) (addrs []string, err error)
LookupIPAddr(ctx context.Context, host string) ([]IPAddr, error)
LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)*/
