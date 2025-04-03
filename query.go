package recursive

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ErrInvalidDomainName = errors.New("invalid domain name")
var ErrNoNameservers = errors.New("no nameservers")

type query struct {
	*Recursive
	start time.Time
	cache Cacher
	logw  io.Writer
	depth int
}

func (q *query) dbg() bool {
	return q.logw != nil
}

func (q *query) log(format string, args ...any) bool {
	fmt.Fprintf(q.logw, "[%-5d %2d] %*s", time.Since(q.start).Milliseconds(), q.depth, q.depth, "")
	fmt.Fprintf(q.logw, format, args...)
	return false
}

func (r *Recursive) runQuery(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	q := &query{
		Recursive: r,
		cache:     cache,
		start:     time.Now(),
		logw:      logw,
	}
	msg, srv, err = q.run(ctx, qname, qtype)
	if logw != nil {
		if msg != nil {
			fmt.Fprintf(logw, "\n%v", msg)
		}
		fmt.Fprintf(logw, "\n;; Query time: %v\n;; SERVER: %v\n", time.Since(q.start).Round(time.Millisecond), srv)
		if err != nil {
			fmt.Fprintf(logw, ";; ERROR: %v\n", err)
		}
	}
	return
}

func serversOrTypeNS(servers []netip.Addr, qtype uint16) (err error) {
	if len(servers) == 0 {
		if qtype != dns.TypeNS {
			err = ErrNoNameservers
		}
	}
	return
}

func (q *query) run(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	qname = dns.CanonicalName(qname)
	servers := []netip.Addr{q.rootServers[0]}
	if msg, servers, err = q.queryNS(ctx, servers, qname, 1); err == nil {
		if err = serversOrTypeNS(servers, qtype); err == nil {
			q.depth++
			for _, server := range servers {
				if msg, err = q.exchange(ctx, server, qname, qtype); err == nil {
					srv = server
					break
				}
			}
		}
	}
	return
}

func (q *query) queryNS(ctx context.Context, servers []netip.Addr, qname string, qlabel int) (msg *dns.Msg, next []netip.Addr, err error) {
	if q.depth > 30 {
		err = ErrMaxDepth
		return
	}
	q.depth++
	defer func() { q.depth-- }()

	idx, _ := dns.PrevLabel(qname, qlabel)

	for _, server := range servers {
		if msg, err = q.exchange(ctx, server, qname[idx:], dns.TypeNS); err == nil && msg != nil {
			next = extractGlue(msg)
			if len(next) == 0 {
				noglue := extractNoGlue(msg, qname[idx:])
				if len(noglue) > 0 {
					_ = q.dbg() && q.log("NS without glue: %v\n", noglue)
					for _, ns := range noglue {
						if m, _, e := q.run(ctx, ns, dns.TypeA); e == nil {
							for _, rr := range m.Answer {
								var ip net.IP
								switch rr := rr.(type) {
								case *dns.A:
									ip = rr.A
								case *dns.AAAA:
									ip = rr.AAAA
								}
								if ip != nil {
									if addr, ok := netip.AddrFromSlice(ip); ok {
										next = append(next, addr)
									}
								}
							}
							break
						}
					}
				}
			}
			if len(next) > 0 {
				_ = q.dbg() && q.log("%v NS for %q: %v\n", len(next), qname[idx:], next[:min(4, len(next))])
				if idx > 0 {
					oldNext := next
					oldMsg := msg
					if msg, next, err = q.queryNS(ctx, next, qname, qlabel+1); len(next) == 0 {
						next = oldNext
						msg = oldMsg
					}
				}
			}
			return
		}
	}
	_ = q.dbg() && q.log("NS not found for %q: %v\n", qname[idx:], err)
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

func extractGlue(msg *dns.Msg) (servers []netip.Addr) {
	for _, rr := range msg.Extra {
		if a, ok := rr.(*dns.A); ok {
			if addr, ok := netip.AddrFromSlice(a.A); ok {
				servers = append(servers, addr)
			}
		}
	}
	return
}

func extractNoGlue(msg *dns.Msg, filtersuffix string) (servers []string) {
	for _, rrs := range [][]dns.RR{msg.Ns, msg.Answer} {
		for _, rr := range rrs {
			if ns, ok := rr.(*dns.NS); ok {
				if !strings.HasSuffix(ns.Ns, filtersuffix) {
					servers = append(servers, ns.Ns)
				}
			}
		}
	}
	return
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

func (q *query) exchangeUsing(ctx context.Context, protocol string, useCookies bool, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	if q.cache != nil {
		if _, msg = q.cache.DnsGet(nsaddr, qname, qtype); msg != nil {
			if q.dbg() {
				q.log("cached answer: @%s %s %q => %s [%v+%v+%v A/N/E]\n",
					nsaddr, DnsTypeToString(qtype), qname,
					dns.RcodeToString[msg.Rcode],
					len(msg.Answer), len(msg.Ns), len(msg.Extra))
			}
			return
		}
	}

	if err = q.getUsable(ctx, protocol, nsaddr); err == nil {
		var network string
		if nsaddr.Is4() {
			network = protocol + "4"
		} else {
			network = protocol + "6"
		}

		if q.rateLimiter != nil {
			<-q.rateLimiter
		}

		if q.dbg() {
			var protostr string
			var dash6str string
			if protocol != "udp" {
				protostr = " +" + protocol
			}
			if nsaddr.Is6() {
				dash6str = " -6"
			}
			q.log("SENDING %s: @%s%s%s %s %q", network, nsaddr, protostr, dash6str, DnsTypeToString(qtype), qname)
		}

		var nconn net.Conn
		var rtt time.Duration

		if q.Timeout > 0 {
			ctx2, cancel := context.WithTimeout(ctx, q.Timeout)
			defer cancel()
			ctx = ctx2
		}

		if nconn, err = q.DialContext(ctx, network, netip.AddrPortFrom(nsaddr, 53).String()); err == nil {
			dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
			defer dnsconn.Close()

			m := new(dns.Msg)
			m.SetQuestion(qname, qtype)

			var hasSrvCookie bool
			var clicookie, srvcookie string

			if useCookies {
				q.mu.RLock()
				cookiernd := q.cookiernd
				srvcookie, hasSrvCookie = q.srvcookies[nsaddr]
				q.mu.RUnlock()

				useCookies = !hasSrvCookie || srvcookie != ""

				if useCookies {
					var h maphash.Hash
					cookiebuf := make([]byte, 8)
					binary.NativeEndian.PutUint64(cookiebuf, cookiernd)
					h.Write(cookiebuf)
					h.Write(nsaddr.AsSlice())
					if la := nconn.LocalAddr(); la != nil {
						h.WriteString(la.String())
					}
					clicookie = hex.EncodeToString(h.Sum(nil))

					opt := new(dns.OPT)
					opt.Hdr.Name = "."
					opt.Hdr.Rrtype = dns.TypeOPT
					opt.SetUDPSize(dns.DefaultMsgSize)
					opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
						Code:   dns.EDNS0COOKIE,
						Cookie: clicookie + srvcookie,
					})
					m.Extra = append(m.Extra, opt)
				}
			}

			c := dns.Client{UDPSize: dns.DefaultMsgSize}
			msg, rtt, err = c.ExchangeWithConnContext(ctx, m, dnsconn)
			if useCookies && msg != nil {
				newsrvcookie := srvcookie
				if opt := msg.IsEdns0(); opt != nil {
					for _, rr := range opt.Option {
						switch rr := rr.(type) {
						case *dns.EDNS0_COOKIE:
							if strings.HasPrefix(rr.Cookie, clicookie) {
								newsrvcookie = strings.TrimPrefix(rr.Cookie, clicookie)
							} else {
								msg = nil
								err = ErrInvalidCookie
							}
						}
					}
				}
				if !hasSrvCookie || srvcookie != newsrvcookie {
					q.mu.Lock()
					q.srvcookies[nsaddr] = newsrvcookie
					q.mu.Unlock()
				}
			}
		}

		isIpv6Err, isUdpErr := q.setNetError(protocol, nsaddr, err)
		ipv6disabled := isIpv6Err && q.maybeDisableIPv6(err)
		udpDisabled := isUdpErr && q.maybeDisableUdp(err)

		if q.logw != nil {
			if msg != nil {
				fmt.Fprintf(q.logw, " => %s [%v+%v+%v A/N/E] (%v, %d bytes",
					dns.RcodeToString[msg.Rcode],
					len(msg.Answer), len(msg.Ns), len(msg.Extra),
					rtt.Round(time.Millisecond), msg.Len())
				if msg.MsgHdr.Truncated {
					fmt.Fprintf(q.logw, " TRNC")
				}
				if msg.MsgHdr.Authoritative {
					fmt.Fprintf(q.logw, " AUTH")
				}
				if opt := msg.IsEdns0(); opt != nil {
					if er := opt.ExtendedRcode(); er != 0 {
						fmt.Fprintf(q.logw, " EDNS=%s", dns.ExtendedErrorCodeToString[uint16(er)])
					}
				}
				fmt.Fprintf(q.logw, ")")
			}
			if err != nil {
				fmt.Fprintf(q.logw, " error: %v", err)
			}
			if ipv6disabled {
				fmt.Fprintf(q.logw, " (IPv6 disabled)")
			}
			if udpDisabled {
				fmt.Fprintf(q.logw, " (UDP disabled)")
			}
			fmt.Fprintln(q.logw)
		}
	}

	return
}

func (q *query) exchange(ctx context.Context, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	useCookies := true
	if q.usingUDP() {
		msg, err = q.exchangeUsing(ctx, "udp", useCookies, nsaddr, qname, qtype)
		if msg != nil {
			if msg.MsgHdr.Truncated {
				msg = nil
				_ = q.dbg() && q.log("message truncated; retry using TCP\n")
			} else if msg.MsgHdr.Rcode == dns.RcodeFormatError {
				msg = nil
				_ = q.dbg() && q.log("got FORMERR, retry using TCP without cookies\n")
				useCookies = false
			}
		}
	}
	if (msg == nil || err != nil) && q.useable(nsaddr) {
		msg, err = q.exchangeUsing(ctx, "tcp", useCookies, nsaddr, qname, qtype)
	}
	if err == nil && q.cache != nil {
		q.cache.DnsSet(nsaddr, msg)
	}
	return
}
