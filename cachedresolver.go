package recursive

import (
	"context"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type CachedResolver struct {
	proxy.ContextDialer
	*Recursive
	*net.Resolver
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
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     cd.DialContext,
		},
		Cacher: cacher,
	}
}

func (std *CachedResolver) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return std.Recursive.ResolveWithOptions(ctx, std, std, nil, qname, qtype)
}

// override some of the standard Go net.Resolver functions

func (std *CachedResolver) lookupNetIP(ctx context.Context, ips []net.IP, host string, qtype uint16) ([]net.IP, error) {
	msg, _, err := std.DnsResolve(ctx, host, qtype)
	if err == nil {
		for _, rr := range msg.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				ips = append(ips, rr.A)
			case *dns.AAAA:
				ips = append(ips, rr.AAAA)
			}
		}
	}
	return ips, err
}

func (std *CachedResolver) LookupNetIP(ctx context.Context, network, host string) (ips []net.IP, err error) {
	if network == "ip" || network == "ip4" {
		ips, err = std.lookupNetIP(ctx, ips, host, dns.TypeA)
	}
	if network == "ip" || network == "ip6" {
		ips, err = std.lookupNetIP(ctx, ips, host, dns.TypeAAAA)
	}
	if len(ips) > 0 {
		err = nil
	}
	return
}

func (std *CachedResolver) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	var ips []net.IP
	if ips, err = std.LookupNetIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
	}
	return
}

func (std *CachedResolver) LookupIPAddr(ctx context.Context, host string) (addrs []net.IPAddr, err error) {
	var ips []net.IP
	if ips, err = std.LookupNetIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			addrs = append(addrs, net.IPAddr{IP: ip})
		}
	}
	return
}

// func (std *CachedResolver) LookupAddr(ctx context.Context, addr string) ([]string, error)
// func (std *CachedResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error)
// func (std *CachedResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error)
// func (std *CachedResolver) LookupPort(ctx context.Context, network, service string) (port int, err error)
// func (std *CachedResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
// func (std *CachedResolver) LookupTXT(ctx context.Context, name string) ([]string, error)
