package recursive

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"github.com/miekg/dns"
)

// Standard Go net.Resolver function overrides

// LookupIP looks up host and returns a slice of its IPv4 and IPv6 addresses.
func (rc *Recursive) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	seen := make(map[string]struct{})
	var ips []net.IP

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
		if list, err := rc.lookupNetIP(ctx, host, dns.TypeA); err == nil {
			add(list)
		}
	}

	if network == "ip" || network == "ip6" {
		if list, err := rc.lookupNetIP(ctx, host, dns.TypeAAAA); err == nil {
			add(list)
		}
	}

	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return ips, nil
}

// LookupHost looks up the given host and returns a slice of its addresses.
func (rc *Recursive) LookupHost(ctx context.Context, host string) ([]string, error) {
	ips, err := rc.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.String()
	}

	return addrs, nil
}

// LookupNetIP looks up host and returns a slice of its IP addresses.
func (rc *Recursive) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	ips, err := rc.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, addr)
		}
	}

	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addrs), nil
}

// LookupIPAddr looks up host and returns a slice of its net.IPAddr records.
func (rc *Recursive) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	ips, err := rc.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	addrs := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		addrs[i] = net.IPAddr{IP: ip}
	}

	return addrs, nil
}

// LookupNS looks up the NS records for the given domain name.
func (rc *Recursive) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	msg, _, err := rc.dnsResolve(ctx, name, dns.TypeNS)
	if err != nil {
		return nil, err
	}

	var nslist []*net.NS
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nslist = append(nslist, &net.NS{Host: ns.Ns})
		}
	}

	return nslist, nil
}

func (rc *Recursive) lookupNetIP(ctx context.Context, host string, qtype uint16) ([]net.IP, error) {
	msg, _, err := rc.dnsResolve(ctx, host, qtype)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, rr := range msg.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			ips = append(ips, rr.AAAA)
		}
	}

	return ips, nil
}
