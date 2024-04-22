package recursive

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type Standard struct {
	proxy.ContextDialer
	*Recursive
	Cacher
}

var DefaultStandard = NewStandard(nil, nil, nil)

func NewStandard(rec *Recursive, cd proxy.ContextDialer, cacher Cacher) CachingResolver {
	if rec == nil {
		rec = New()
	}
	if cd == nil {
		cd = &defaultNetDialer
	}
	if cacher == nil {
		cacher = DefaultCache
	}
	return &Standard{
		ContextDialer: cd,
		Recursive:     rec,
		Cacher:        cacher,
	}
}

func (std *Standard) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return std.Recursive.ResolveWithOptions(ctx, std, std, nil, qname, qtype)
}
