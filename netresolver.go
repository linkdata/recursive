package recursive

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"github.com/miekg/dns"
)

// override some of the standard Go net.Resolver functions

func (rc *Recursive) lookupNetIP(ctx context.Context, host string, qtype uint16) (ips []net.IP, err error) {
	var msg *dns.Msg
	if msg, _, err = rc.dnsResolve(ctx, host, qtype); msg != nil {
		for _, rr := range msg.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				ips = append(ips, rr.A)
			case *dns.AAAA:
				ips = append(ips, rr.AAAA)
			}
		}
	}
	return
}

func (rc *Recursive) LookupIP(ctx context.Context, network, host string) (ips []net.IP, err error) {
	seen := map[string]struct{}{}
	add := func(list []net.IP) {
		for _, ip := range list {
			key := ip.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				ips = append(ips, ip)
			}
		}
	}
	if network == "ip" || network == "ip4" {
		var list []net.IP
		if list, err = rc.lookupNetIP(ctx, host, dns.TypeA); err == nil {
			add(list)
		}
	}
	if network == "ip" || network == "ip6" {
		var list []net.IP
		if list, err = rc.lookupNetIP(ctx, host, dns.TypeAAAA); err == nil {
			add(list)
		}
	}
	if len(ips) > 0 {
		err = nil
	}
	return
}

func (rc *Recursive) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	var ips []net.IP
	if ips, err = rc.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
	}
	return
}

func (rc *Recursive) LookupNetIP(ctx context.Context, network, host string) (addrs []netip.Addr, err error) {
	var ips []net.IP
	if ips, err = rc.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			if ip, ok := netip.AddrFromSlice(ip); ok {
				addrs = append(addrs, ip)
			}
		}
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		addrs = slices.Compact(addrs)
	}
	return
}

func (rc *Recursive) LookupIPAddr(ctx context.Context, host string) (addrs []net.IPAddr, err error) {
	var ips []net.IP
	if ips, err = rc.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			addrs = append(addrs, net.IPAddr{IP: ip})
		}
	}
	return
}

func (rc *Recursive) LookupNS(ctx context.Context, name string) (nslist []*net.NS, err error) {
	var msg *dns.Msg
	if msg, _, err = rc.dnsResolve(ctx, name, dns.TypeNS); err == nil {
		for _, rr := range msg.Answer {
			switch rr := rr.(type) {
			case *dns.NS:
				nslist = append(nslist, &net.NS{Host: rr.Ns})
			}
		}
	}
	return
}

// func (std *Recursive) LookupAddr(ctx context.Context, addr string) ([]string, error)
// func (std *Recursive) LookupMX(ctx context.Context, name string) ([]*net.MX, error)
// func (std *Recursive) LookupPort(ctx context.Context, network, service string) (port int, err error)
// func (std *Recursive) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
// func (std *Recursive) LookupTXT(ctx context.Context, name string) ([]string, error)
