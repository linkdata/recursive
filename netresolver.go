package recursive

import (
	"context"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// override some of the standard Go net.Resolver functions

func (std *Recursive) lookupNetIP(ctx context.Context, ips []net.IP, host string, qtype uint16) ([]net.IP, error) {
	msg, _, err := std.DnsResolve(ctx, host, qtype)
	if msg != nil {
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

func (std *Recursive) LookupIP(ctx context.Context, network, host string) (ips []net.IP, err error) {
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

func (std *Recursive) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	var ips []net.IP
	if ips, err = std.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
	}
	return
}

func (std *Recursive) LookupNetIP(ctx context.Context, network, host string) (addrs []netip.Addr, err error) {
	var ips []net.IP
	if ips, err = std.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			if ip, ok := netip.AddrFromSlice(ip); ok {
				addrs = append(addrs, ip)
			}
		}
	}
	return
}

func (std *Recursive) LookupIPAddr(ctx context.Context, host string) (addrs []net.IPAddr, err error) {
	var ips []net.IP
	if ips, err = std.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			addrs = append(addrs, net.IPAddr{IP: ip})
		}
	}
	return
}

func (std *Recursive) LookupNS(ctx context.Context, name string) (nslist []*net.NS, err error) {
	var msg *dns.Msg
	if msg, _, err = std.DnsResolve(ctx, name, dns.TypeNS); err == nil {
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
