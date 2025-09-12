package recursive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	cacheExtra = true // set to false to debug glue lookups
)

type query struct {
	*Recursive
	start  time.Time
	cache  Cacher
	logw   io.Writer
	depth  int
	nomini bool
	sent   int
	steps  int
	glue   map[string][]netip.Addr
	cnames map[string]struct{}
}

func (q *query) dbg() bool {
	return q.logw != nil
}

func (q *query) log(format string, args ...any) bool {
	fmt.Fprintf(q.logw, "[%-5d %2d] %*s", time.Since(q.start).Milliseconds(), q.depth, q.depth, "")
	fmt.Fprintf(q.logw, format, args...)
	return false
}

func maskCookie(s string) string {
	if len(s) > 8 {
		return s[:8] + "..."
	}
	return s
}

type hostAddr struct {
	host string
	addr netip.Addr
}

func (ha hostAddr) String() (s string) {
	s = ha.host
	if ha.addr.IsValid() {
		s += " " + ha.addr.String()
	}
	return
}

// needGlue returns true if the host was added to the glue map
func (q *query) needGlue(host string) (yes bool) {
	if _, ok := q.glue[host]; !ok {
		yes = true
		q.glue[host] = nil
	}
	return
}

// addGlue adds the addr to the glue map for host if it exists and addr is usable
func (q *query) addGlue(host string, addr netip.Addr) {
	if q.useable(addr) {
		if addrs, ok := q.glue[host]; ok {
			if !slices.Contains(addrs, addr) {
				q.glue[host] = append(addrs, addr)
			}
		}
	}
}

func (q *query) setCache(msg *dns.Msg) {
	if msg != nil && !msg.Zero {
		if q.cache != nil && !q.nomini {
			q.cache.DnsSet(msg)
		}
	}
}

func (q *query) glueTypes() (gt []uint16) {
	if q.useIPv4 {
		gt = append(gt, dns.TypeA)
	}
	if q.useIPv6 {
		gt = append(gt, dns.TypeAAAA)
	}
	return
}

// run performs a recursive resolution for the given name and type.
func (q *query) run(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	if err = q.dive(); err == nil {
		defer q.surface()

		var (
			nslist []hostAddr // current set of servers to query
			final  bool       // past the last part of the name
			idx    int        // start of current label
			qlabel int        // label to query for, starting from the right
		)

		qname = dns.CanonicalName(qname)
		nslist = q.getRootServers()

		for !final {
			qlabel++
			idx, final = dns.PrevLabel(qname, qlabel)
			cqname := qname[idx:] // current name to ask for
			cqtype := dns.TypeNS  // current type to ask for
			if q.nomini {
				cqname = qname
				cqtype = qtype
			}
			if _, ok := q.glue[qname]; ok {
				cqtype = qtype
			}

			if q.dbg() {
				finalText := ""
				if final {
					finalText = " FINAL"
				}
				q.log("QUERY%s %s %q from %v\n", finalText, DnsTypeToString(cqtype), cqname, nslist[:min(4, len(nslist))])
			}

			var (
				nsrcode int      // RCODE from last nameserver A query resolving glueless names
				gotmsg  *dns.Msg // last valid response
			)

			for _, ha := range nslist {
				if !ha.addr.IsValid() {
					if q.needGlue(ha.host) {
						_ = q.dbg() && q.log("GLUE lookup for NS %q\n", ha.host)
						for _, gluetype := range q.glueTypes() {
							var m *dns.Msg
							if m, _, err = q.run(ctx, ha.host, gluetype); err == nil {
								nsrcode = m.Rcode
								if m.Rcode == dns.RcodeSuccess {
									for _, rr := range m.Answer {
										if host, addr := rrHostAddr(rr); host == ha.host {
											ha.addr = addr
											q.addGlue(host, addr)
										}
									}
								}
							}
						}
					}
				}
				if q.useable(ha.addr) {
					if gotmsg, err = q.exchange(ctx, ha.addr, cqname, cqtype); err == nil {
						switch gotmsg.Rcode {
						case dns.RcodeSuccess:
							if gotmsg.Authoritative || (idx > 0 && (nsrcode == dns.RcodeNameError || len(gotmsg.Answer) > 0)) {
								q.setCache(gotmsg)
							}
							if q.nomini && qtype != dns.TypeCNAME {
								if m, handled := q.handleCNAME(ctx, gotmsg, qname, qtype); handled {
									msg = m
									return
								}
							}
							newlist := q.extractNS(gotmsg)
							if len(newlist) > 0 {
								srv = ha.addr
								msg = gotmsg
								nslist = newlist
							}
						case dns.RcodeServerFailure:
							if final {
								q.setCache(gotmsg)
								srv = ha.addr
								msg = gotmsg
								return
							}
							msg = nil
							srv = ha.addr
							continue
						case dns.RcodeRefused:
							if !q.nomini {
								_ = q.dbg() && q.log("got REFUSED, retry without QNAME minimization\n")
								q.nomini = true
								msg, srv, err = q.run(ctx, qname, qtype)
								return
							}
							fallthrough
						default:
							q.setCache(gotmsg)
							srv = ha.addr
							msg = gotmsg
							return
						}
						break // next qlabel
					}
				}
			}

			// asked all nameservers or got a usable answer
			if gotmsg == nil {
				_ = q.dbg() && q.log("no ANSWER for %s %q (%s)\n", DnsTypeToString(qtype), qname, dns.RcodeToString[nsrcode])
				if msg != nil {
					if qtype == dns.TypeNS {
						if len(msg.Answer) == 0 {
							if len(msg.Question) > 0 && msg.Question[0].Name == qname {
								msg.Answer, msg.Ns = msg.Ns, msg.Answer
							} else {
								msg.Rcode = nsrcode
							}
						}
					} else {
						if nsrcode != dns.RcodeSuccess {
							msg.SetQuestion(qname, qtype)
							msg.Rcode = nsrcode
						}
					}
				} else {
					err = errors.Join(err, ErrNoResponse)
				}
			} else {
				if msg == nil {
					_ = q.dbg() && q.log("all nameservers returned SERVFAIL\n")
					q.setCache(gotmsg)
					msg = gotmsg
				}
			}
		}

		// ask the final nameserves for the record
		if msg != nil {
			var nsaddrs []netip.Addr
			for _, ha := range nslist {
				if ha.addr.IsValid() {
					nsaddrs = append(nsaddrs, ha.addr)
				} else {
					nsaddrs = append(nsaddrs, q.glue[ha.host]...)
				}
			}
			slices.SortFunc(nsaddrs, func(a, b netip.Addr) int { return a.Compare(b) })
			nsaddrs = slices.Compact(nsaddrs)
			if q.dbg() {
				q.log("final nameservers: %v\n", nsaddrs)
				if q.depth == 1 {
					keys := slices.Collect(maps.Keys(q.glue))
					slices.Sort(keys)
					for _, k := range keys {
						q.log("glue: %q: %v\n", k, q.glue[k])
					}
				}
			}
			for _, nsaddr := range nsaddrs {
				var finalmsg *dns.Msg
				if finalmsg, err = q.exchange(ctx, nsaddr, qname, qtype); err == nil && finalmsg.Rcode != dns.RcodeServerFailure {
					msg = finalmsg
					q.setCache(msg)
					if qtype != dns.TypeCNAME {
						if m, handled := q.handleCNAME(ctx, msg, qname, qtype); handled {
							msg = m
							return
						}
					}
					break
				} else {
					_ = q.dbg() && q.log("FAILED @%v %s %q: %v\n", nsaddr, DnsTypeToString(qtype), qname, err)
				}
			}
			if err != nil || len(nsaddrs) == 0 {
				// all final nameservers failed to be queried,
				// so don't use the last NS message unless usable
				if msg == nil || qtype != dns.TypeNS || qname != msg.Question[0].Name {
					msg = nil
				}
			}
		}

		if msg == nil {
			// manufacture a SERVFAIL
			msg = new(dns.Msg)
			msg.SetQuestion(qname, qtype)
			msg.Rcode = dns.RcodeServerFailure
		} else {
			// we got a message to return, disregard network errors
			err = nil
		}

		_ = q.dbg() && q.log("ANSWER %s for %s %q with %d records\n",
			dns.RcodeToString[msg.Rcode],
			DnsTypeToString(qtype), qname,
			len(msg.Answer))
	}
	return
}

// handleCNAME follows a CNAME in msg if present. It returns the updated
// message and a boolean indicating whether a CNAME was followed and the caller
// should return immediately.
func (q *query) handleCNAME(ctx context.Context, base *dns.Msg, qname string, qtype uint16) (*dns.Msg, bool) {
	for _, rr := range base.Answer {
		cn, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		target := dns.CanonicalName(cn.Target)
		if !q.followCNAME(target) {
			continue
		}
		_ = q.dbg() && q.log("CNAME QUERY %q => %q\n", qname, target)
		if cnmsg, _, err := q.run(ctx, target, qtype); err == nil {
			_ = q.dbg() && q.log("CNAME ANSWER %s %q with %v records\n", dns.RcodeToString[cnmsg.Rcode], target, len(cnmsg.Answer))
			msg := base.Copy()
			msg.Zero = true
			msg.Answer = append(msg.Answer, cnmsg.Answer...)
			msg.Rcode = cnmsg.Rcode
			return msg, true
		} else {
			_ = q.dbg() && q.log("CNAME ERROR %q: %v\n", target, err)
		}
	}
	return base, false
}

func rrHostAddr(rr dns.RR) (host string, addr netip.Addr) {
	switch v := rr.(type) {
	case *dns.A:
		if ip, ok := netip.AddrFromSlice(v.A); ok {
			host = dns.CanonicalName(v.Hdr.Name)
			addr = ip.Unmap()
		}
	case *dns.AAAA:
		if ip, ok := netip.AddrFromSlice(v.AAAA); ok {
			host = dns.CanonicalName(v.Hdr.Name)
			addr = ip
		}
	}
	return
}

func (q *query) extractNS(msg *dns.Msg) (hal []hostAddr) {
	nsmap := map[string]struct{}{}
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range rrs {
			switch rr := rr.(type) {
			case *dns.NS:
				host := dns.CanonicalName(rr.Ns)
				nsmap[host] = struct{}{}
			}
			host, addr := rrHostAddr(rr)
			q.addGlue(host, addr)
		}
	}
	for _, rr := range msg.Extra {
		host, addr := rrHostAddr(rr)
		if _, ok := nsmap[host]; ok {
			q.needGlue(host)
			q.addGlue(host, addr)
		}
	}
	for host := range nsmap {
		addrs := q.glue[host]
		if len(addrs) == 0 {
			hal = append(hal, hostAddr{host: host})
		} else {
			for _, addr := range addrs {
				hal = append(hal, hostAddr{host: host, addr: addr})
			}
		}
	}
	// Make the NS query order deterministic.
	slices.SortFunc(hal, func(a, b hostAddr) int {
		if a.addr.IsValid() {
			if b.addr.IsValid() {
				return a.addr.Compare(b.addr)
			}
			return -1
		}
		if b.addr.IsValid() {
			return 1
		}
		n := strings.Count(a.host, ".") - strings.Count(b.host, ".")
		if n == 0 {
			n = strings.Compare(a.host, b.host)
		}
		return n
	})
	return
}

func (q *query) dive() (err error) {
	err = ErrMaxDepth
	if q.depth < maxDepth {
		q.depth++
		err = nil
	}
	return
}

func (q *query) surface() {
	q.depth--
}

func (q *query) followCNAME(cn string) bool {
	if q.cnames == nil {
		q.cnames = make(map[string]struct{})
	}
	_, ok := q.cnames[cn]
	if !ok {
		q.cnames[cn] = struct{}{}
	}
	return !ok
}

func (q *query) exchangeUsing(ctx context.Context, protocol string, useCookies bool, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	q.steps++
	if q.steps > maxSteps {
		err = ErrMaxSteps
		return
	}
	if q.cache != nil && !q.nomini {
		if msg = q.cache.DnsGet(qname, qtype); msg != nil {
			if !cacheExtra {
				msg.Extra = nil
			}
			if q.dbg() {
				auth := ""
				if msg.MsgHdr.Authoritative {
					auth = " AUTH"
				}
				q.log("cached answer: %s %q => %s [%v+%v+%v A/N/E]%s\n",
					DnsTypeToString(qtype), qname,
					dns.RcodeToString[msg.Rcode],
					len(msg.Answer), len(msg.Ns), len(msg.Extra),
					auth,
				)
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

		if nconn, err = q.DialContext(ctx, network, netip.AddrPortFrom(nsaddr, q.DNSPort).String()); err == nil {
			q.sent++
			dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
			defer dnsconn.Close()

			m := new(dns.Msg)
			m.SetQuestion(qname, qtype)
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetUDPSize(dns.DefaultMsgSize)

			var hasSrvCookie bool
			var clicookie, srvcookie string

			if useCookies {
				clicookie = q.clicookie
				srvcookie, hasSrvCookie = q.getSrvCookie(nsaddr)

				useCookies = !hasSrvCookie || srvcookie != ""

				if useCookies {
					opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
						Code:   dns.EDNS0COOKIE,
						Cookie: clicookie + srvcookie,
					})
					if q.logw != nil {
						fmt.Fprintf(q.logw, " COOKIE:c=%q s=%q", maskCookie(clicookie), maskCookie(srvcookie))
					}
				}
			}
			m.Extra = append(m.Extra, opt)
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
					q.setSrvCookie(nsaddr, newsrvcookie)
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
					if er := uint16(opt.ExtendedRcode()); /*#nosec G115*/ er != 0 {
						fmt.Fprintf(q.logw, " EDNS=%s", dns.ExtendedErrorCodeToString[er])
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
				_ = q.dbg() && q.log("message truncated; retry using TCP\n")
				msg = nil
			} else if msg.MsgHdr.Rcode == dns.RcodeFormatError {
				_ = q.dbg() && q.log("got FORMERR, retry using TCP without cookies\n")
				msg = nil
				useCookies = false
			}
		}
	}
	if (msg == nil || err != nil) && q.useable(nsaddr) {
		msg, err = q.exchangeUsing(ctx, "tcp", useCookies, nsaddr, qname, qtype)
	}
	return
}
