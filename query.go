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

func updateCookies(msg *dns.Msg) {
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if cookie, ok := option.(*dns.EDNS0_COOKIE); ok && len(cookie.Cookie) >= 16 {
					serverCookie := cookie.Cookie[16:]
					_ = serverCookie
				}
			}
		}
	}
}

func (r *Recursive) resolveNSWithDNS(ctx context.Context, msg *dns.Msg) ([]string, error) {
	var servers []string
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsResponse, err := r.LookupHost(ctx, ns.Ns)
			if err != nil || len(nsResponse) == 0 {
				continue
			}
			for _, ans := range nsResponse {
				servers = append(servers, ans+":53")
			}
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("no NS servers resolved")
	}
	return servers, nil
}
