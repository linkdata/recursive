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
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ErrInvalidDomainName = errors.New("invalid domain name")
var ErrNoNameservers = errors.New("no nameservers")
var ErrQuestionMismatch = errors.New("question mismatch")

type query struct {
	*Recursive
	start  time.Time
	cache  Cacher
	logw   io.Writer
	depth  int
	nomini bool
	count  int
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

func (r *Recursive) runQuery(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	var q *query
	qname = dns.CanonicalName(qname)
	if cache != nil {
		msg = cache.DnsGet(qname, qtype)
	}
	if msg == nil {
		q = &query{
			Recursive: r,
			cache:     cache,
			start:     time.Now(),
			logw:      logw,
			glue:      make(map[string][]netip.Addr),
		}
		msg, srv, err = q.run(ctx, qname, qtype)
	}
	if msg != nil {
		if msg.Rcode == dns.RcodeSuccess {
			// A SUCCESS reply must reference the correct QNAME and QTYPE.
			if msg.Question[0].Name != qname || msg.Question[0].Qtype != qtype {
				err = ErrQuestionMismatch
				_ = q.dbg() && q.log("ERROR: ANSWER was for %s %q, not %s %q\n",
					DnsTypeToString(msg.Question[0].Qtype), msg.Question[0].Name,
					DnsTypeToString(qtype), qname,
				)
			}
		} else {
			// NXDOMAIN or other failures may have the returned
			// question refer to some NS in the chain, but we still want
			// to associate the reply with the original query.
			msg.Question[0].Name = qname
			msg.Question[0].Qtype = qtype
		}
		if err == nil {
			cache.DnsSet(msg)
		}
	}
	if logw != nil {
		if msg != nil {
			fmt.Fprintf(logw, "\n%v", msg)
		}
		if q != nil {
			fmt.Fprintf(logw, "\n;; Sent %v queries in %v", q.count, time.Since(q.start).Round(time.Millisecond))
		}
		if srv.IsValid() {
			fmt.Fprintf(logw, "\n;; SERVER: %v", srv)
		}
		if err != nil {
			fmt.Fprintf(logw, "\n;; ERROR: %v", err)
		}
		fmt.Fprintln(logw)
	}
	return
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

func (q *query) addGlue(host string, addr netip.Addr) {
	addrs := q.glue[host]
	if !slices.Contains(addrs, addr) {
		q.glue[host] = append(addrs, addr)
	}
}

func (q *query) run(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	if err = q.dive(); err == nil {
		defer q.surface()

		qname = dns.CanonicalName(qname)

		nslist := []hostAddr{{"root", q.rootServers[0]}} // current set of servers to query
		var final bool                                   // at the last part of the name
		var idx int                                      // start of current label
		var qlabel int                                   // label to query for, starting from the right

		for !final {
			qlabel++
			idx, final = dns.PrevLabel(qname, qlabel)
			cqname := qname[idx:] // current name to ask for
			cqtype := dns.TypeNS  // current type to ask for
			if final || q.nomini {
				cqname = qname
				cqtype = qtype
			}

			_ = q.dbg() && q.log("QUERY %s %q from %v\n", DnsTypeToString(cqtype), cqname, nslist[:min(4, len(nslist))])
			var nsrcode int     // RCODE from last nameserver query
			var gotmsg *dns.Msg // last valid response
			for _, ha := range nslist {
				if !ha.addr.IsValid() {
					var m *dns.Msg
					if m, _, err = q.run(ctx, ha.host, dns.TypeA); err == nil {
						nsrcode = m.Rcode
						if m.Rcode == dns.RcodeSuccess {
							for _, rr := range m.Answer {
								if host, addr := rrHostAddr(rr); host == ha.host {
									ha.addr = addr
									break
								}
							}
						}

					}
				}
				if ha.addr.IsValid() {
					if gotmsg, err = q.exchange(ctx, ha.addr, cqname, cqtype); err == nil {
						switch gotmsg.Rcode {
						case dns.RcodeRefused:
							if !q.nomini {
								_ = q.dbg() && q.log("got REFUSED, retry without QNAME minimization\n")
								q.nomini = true
								msg, srv, err = q.run(ctx, qname, qtype)
								return
							}
							final = true
						case dns.RcodeNameError:
							srv = ha.addr
							msg = gotmsg
							return
						case dns.RcodeSuccess:
							newlist := q.extractNS(gotmsg, qname)
							if len(newlist) > 0 {
								srv = ha.addr
								msg = gotmsg
								nslist = newlist
							}
						}
						if final || q.nomini {
							srv = ha.addr
							msg = gotmsg
							if qtype != dns.TypeCNAME {
								for _, rr := range msg.Answer {
									if cn, ok := rr.(*dns.CNAME); ok {
										if q.followCNAME(cn.Target) {
											_ = q.dbg() && q.log("CNAME QUERY %q => %q\n", cqname, cn.Target)
											if cnmsg, _, cnerr := q.run(ctx, cn.Target, qtype); cnerr == nil {
												_ = q.dbg() && q.log("CNAME ANSWER %q with %v records\n", cn.Target, len(cnmsg.Answer))
												if msg.Zero {
													msg = msg.Copy()
													msg.Zero = false
												}
												msg.Answer = append(msg.Answer, cnmsg.Answer...)
												return
											} else {
												_ = q.dbg() && q.log("CNAME ERROR %q: %v\n", cn.Target, cnerr)
											}
										}
									}
								}
							}
						}
						break // next qlabel
					}
				}
			}
			if gotmsg == nil {
				_ = q.dbg() && q.log("no ANSWER for %s %q\n", DnsTypeToString(qtype), qname)
				if msg != nil {
					if nsrcode != dns.RcodeSuccess && qtype != dns.TypeNS {
						msg.Question[0].Name = qname
						msg.Question[0].Qtype = qtype
						msg.Rcode = nsrcode
					}
					if err != nil {
						msg.Rcode = dns.RcodeServerFailure
					}
				}
			}
		}
		if msg != nil {
			_ = q.dbg() && q.log("ANSWER %s for %s %q with %d records\n",
				dns.RcodeToString[msg.Rcode],
				DnsTypeToString(qtype), qname,
				len(msg.Answer))
		}
	}
	return
}

func rrHostAddr(rr dns.RR) (host string, addr netip.Addr) {
	switch v := rr.(type) {
	case *dns.A:
		if ip, ok := netip.AddrFromSlice(v.A); ok {
			host = v.Hdr.Name
			addr = ip.Unmap()
		}
	case *dns.AAAA:
		if ip, ok := netip.AddrFromSlice(v.AAAA); ok {
			host = v.Hdr.Name
			addr = ip
		}
	}
	return
}

func (q *query) extractNS(msg *dns.Msg, filtersuffix string) (hal []hostAddr) {
	nsmap := map[string]struct{}{}
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range rrs {
			switch rr := rr.(type) {
			case *dns.NS:
				if !strings.HasSuffix(rr.Ns, filtersuffix) {
					nsmap[rr.Ns] = struct{}{}
				}
			}
		}
	}
	for _, rr := range msg.Extra {
		if host, addr := rrHostAddr(rr); addr.IsValid() {
			if _, ok := nsmap[host]; ok {
				q.addGlue(host, addr)
			}
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
	if q.cache != nil && !q.nomini {
		if msg = q.cache.DnsGet(qname, qtype); msg != nil {
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
			q.count++
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
					opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
						Code:   dns.EDNS0COOKIE,
						Cookie: clicookie + srvcookie,
					})
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
	if err == nil && q.cache != nil && !q.nomini {
		q.cache.DnsSet(msg)
	}
	return
}
