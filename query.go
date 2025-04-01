package recursive

import (
	"context"
	"errors"

	"github.com/miekg/dns"
)

var ErrInvalidDomainName = errors.New("invalid domain name")

func (r *Recursive) runQuery(ctx context.Context, servers []string, qname string, qtype uint16, qlabel int) (err error) {
	idx, final := dns.PrevLabel(qname, qlabel)
	if !final {
		if _, servers, err = r.queryNS(ctx, servers, qname[idx:]); err == nil {
			err = r.runQuery(ctx, servers, qname, qtype, qlabel+1)
		}
	}
	return
}

func (r *Recursive) queryNS(ctx context.Context, servers []string, qname string) (response *dns.Msg, next []string, err error) {
	for _, server := range servers {
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(qname), dns.TypeNS)
		r.addEDNS(query)
		c := dns.Client{UDPSize: dns.DefaultMsgSize}
		response, _, err = c.Exchange(query, server)
		if err != nil || response == nil {
			continue
		}
		if len(response.Ns) > 0 {
			nextServers := extractGlue(response)
			if len(nextServers) == 0 {
				// nextServers, err = r.resolveNSWithDNS(response)
				if err != nil {
					continue
				}
			}
			return response, nextServers, nil
		}

	}
	return
}

func (r *Recursive) clientCookie() string {
	return ""
}

func (r *Recursive) addEDNS(msg *dns.Msg) {
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
	}
	opt.SetUDPSize(1232)
	cookie := &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: r.clientCookie()}
	opt.Option = append(opt.Option, cookie)
	msg.Extra = append(msg.Extra, opt)
}

func extractGlue(msg *dns.Msg) []string {
	var servers []string
	for _, rr := range msg.Extra {
		if a, ok := rr.(*dns.A); ok {
			servers = append(servers, a.A.String()+":53")
		}
	}
	return servers
}
