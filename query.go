package recursive

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type query struct {
	*Recursive
	cache Cacher
	logw  io.Writer
	start time.Time
	depth int
	steps int
	glue  map[string][]netip.Addr
}

func (q *query) dive(format string, args ...any) (err error) {
	err = ErrMaxSteps
	if q.steps < maxSteps {
		q.steps++
		err = ErrMaxDepth
		if q.depth < maxDepth {
			err = nil
			if format != "" {
				q.logf(format, args...)
			}
			q.depth++
		}
	}
	return
}

func (q *query) surface() {
	q.depth--
}

func (q *query) resolve(ctx context.Context, qname string, qtype uint16) (resp *dns.Msg, srv netip.Addr, err error) {
	var servers []netip.Addr
	qname = dns.CanonicalName(qname)
	if servers, resp, srv, err = q.queryDelegation(ctx, qname, qtype); err == nil {
		if resp.Rcode == dns.RcodeNameError {
			// no need to query final
			resp.Question[0].Qtype = qtype
		} else {
			resp, srv, err = q.queryFinal(ctx, qname, qtype, servers)
		}
	}
	return
}

func (q *query) queryDelegation(ctx context.Context, qname string, qtype uint16) (servers []netip.Addr, resp *dns.Msg, srv netip.Addr, err error) {
	if err = q.dive("DELEGATION QUERY %q\n", qname); err == nil {
		defer func() {
			q.surface()
			rcode := "UNKNOWN"
			if resp != nil {
				rcode = dns.RcodeToString[resp.Rcode]
			} else if err != nil {
				rcode = err.Error()
			}
			q.logf("DELEGATION ANSWER %q: %s with %d servers\n", qname, rcode, len(servers))
		}()

		servers = append([]netip.Addr(nil), q.rootServers...)
		labels := dns.SplitDomainName(qname)

		// Walk down: "." -> "com." -> "example.com."
		for i := len(labels) - 1; i >= 0; i-- {
			zone := dns.Fqdn(strings.Join(labels[i:], "."))
			var nsAddrs []netip.Addr

			if nsAddrs, resp, srv, err = q.queryForDelegation(ctx, zone, servers, qname); err != nil {
				q.logf("DELEGATION ERROR %q: %v\n", zone, err)
				return
			}

			if len(nsAddrs) > 0 {
				// got a new set of servers to query
				servers = q.sortAddrs(nsAddrs)
			}
		}
	}
	return
}

// queryForDelegation performs the QMIN step at `zone` against `parentServers`.
// If servers REFUSE/NOTIMP the minimized NS query, retry with non-QMIN (ask NS for the full qname).
func (q *query) queryForDelegation(ctx context.Context, zone string, parentServers []netip.Addr, fullQname string) (nsAddrs []netip.Addr, resp *dns.Msg, srv netip.Addr, err error) {
	var nsNames []string
retryWithoutQMIN:
	for _, srv = range parentServers {
		if resp, err = q.exchange(ctx, zone, dns.TypeNS, srv); resp != nil && err == nil {
			if resp.Rcode != dns.RcodeSuccess {
				if resp.Rcode != dns.RcodeNameError {
					// probably dns.RcodeRefused or dns.RcodeNotImplemented, retry without QMIN
					if zone != fullQname {
						q.logf("DELEGATION RETRY without QNAME minimization\n")
						zone = fullQname
						goto retryWithoutQMIN
					}
				}
				// NXDOMAIN at parent or we failed even without QMIN
				return
			}

			nsNames, nsAddrs = q.extractDelegationNS(resp, zone)
			if len(nsNames) > 0 {
				if len(nsAddrs) == 0 {
					nsAddrs = q.resolveNSAddrs(ctx, nsNames)
				}
			}
			if len(nsAddrs) > 0 || resp.Authoritative {
				return
			}
		}
	}

	if resp == nil && err == nil {
		err = ErrNoResponse
	}

	return
}

func (q *query) extractDelegationNS(m *dns.Msg, zone string) (nsNames []string, nsAddr []netip.Addr) {
	// extract delegation NS records
	for _, rr := range m.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.EqualFold(ns.Hdr.Name, zone) {
				nsName := dns.CanonicalName(ns.Ns)
				if !slices.Contains(nsNames, nsName) {
					nsNames = append(nsNames, nsName)
				}
			}
		}
	}
	// extract glue records
	for _, rr := range m.Extra {
		var addr netip.Addr
		switch a := rr.(type) {
		case *dns.A:
			addr = ipToAddr(a.A)
		case *dns.AAAA:
			addr = ipToAddr(a.AAAA)
		}
		if addr.IsValid() {
			hdrName := dns.CanonicalName(rr.Header().Name)
			if slices.Contains(nsNames, hdrName) {
				if !slices.Contains(q.glue[hdrName], addr) {
					q.glue[hdrName] = append(q.glue[hdrName], addr)
				}
			}
		}
	}
	// build list of addresses belonging to nsNames
	addrs := map[netip.Addr]struct{}{}
	for _, nsName := range nsNames {
		for _, addr := range q.glue[nsName] {
			addrs[addr] = struct{}{}
		}
	}
	for addr := range addrs {
		nsAddr = append(nsAddr, addr)
	}
	return
}

// queryFinal asks the authoritative (or closest) servers for the target qname/qtype.
// It also performs CNAME/DNAME chasing, with a loop bound controlled by depth.
func (q *query) queryFinal(ctx context.Context, qname string, qtype uint16, authServers []netip.Addr) (resp *dns.Msg, svr netip.Addr, err error) {
	if err = q.dive("QUERY %s %q from %d servers\n", dns.Type(qtype), qname, len(authServers)); err == nil {
		defer func() {
			q.surface()
			q.logf("ANSWER @%s %s %q", svr, dns.Type(qtype), qname)
			q.logResponse(0, resp, err)
		}()
		for _, svr = range authServers {
			if resp, err = q.exchange(ctx, qname, qtype, svr); resp != nil && err == nil {
				if resp.Rcode == dns.RcodeSuccess {
					if !hasRRType(resp.Answer, qtype) {
						if tgt := cnameTarget(resp, qname); tgt != "" {
							q.logf("CNAME @%s %s %q => %q\n", svr, dns.Type(qtype), qname, tgt)
							var msg *dns.Msg
							var origin netip.Addr
							msg, origin, err = q.resolve(ctx, tgt, qtype)
							if err == nil {
								msg = cloneIfCached(msg)
								prependRecords(msg, resp, qname, cnameChainRecords)
								resp = msg
								svr = origin
							}
						} else if tgt := dnameSynthesize(resp, qname); tgt != "" {
							q.logf("DNAME @%s %s %q => %q\n", svr, dns.Type(qtype), qname, tgt)
							var msg *dns.Msg
							var origin netip.Addr
							msg, origin, err = q.resolve(ctx, tgt, qtype)
							if err == nil {
								msg = cloneIfCached(msg)
								prependRecords(msg, resp, qname, dnameRecords)
								resp = msg
								svr = origin
							}
						} else if qtype == dns.TypeNS {
							answers := delegationRecords(resp, qname)
							if len(answers) > 0 {
								// returning parent delegation
								resp = resp.Copy()
								resp.Zero = false
								resp.Answer = answers
								resp.Extra = nil
								resp.Ns = nil
							}
						}
					}
					return
				}

				if resp.Rcode == dns.RcodeNameError {
					return
				}

				// got an unhandled RCODE, try the next server
			}
		}

		if resp == nil && err == nil {
			err = ErrNoResponse
		}
	}
	return
}

// resolveNSAddrs minimally resolves NS owner names to addresses by asking the roots when glue is missing
func (q *query) resolveNSAddrs(ctx context.Context, nsOwners []string) (addrs []netip.Addr) {
	if q.dive("GLUE QUERY %v\n", nsOwners) == nil {
		defer func() {
			q.surface()
			q.logf("GLUE ANSWER %v\n", addrs)
		}()
		resolved := map[netip.Addr]struct{}{}
		for _, host := range nsOwners {
			if msg, _, err := q.resolve(ctx, dns.CanonicalName(host), dns.TypeA); err == nil {
				for _, rr := range msg.Answer {
					if a, ok := rr.(*dns.A); ok {
						if addr := ipToAddr(a.A); addr.IsValid() {
							resolved[addr] = struct{}{}
						}
					}
				}
			}
			if len(resolved) == 0 && q.usingIPv6() {
				if msg, _, err := q.resolve(ctx, dns.CanonicalName(host), dns.TypeAAAA); err == nil {
					for _, rr := range msg.Answer {
						if a, ok := rr.(*dns.AAAA); ok {
							if addr := ipToAddr(a.AAAA); addr.IsValid() {
								resolved[addr] = struct{}{}
							}
						}
					}
				}
			}
		}
		for addr := range resolved {
			addrs = append(addrs, addr)
		}
	}
	return
}

func (q *query) logf(format string, args ...any) {
	if q.logw != nil {
		_, _ = fmt.Fprintf(q.logw, "[%-5d %2d] %*s", time.Since(q.start).Milliseconds(), q.depth, q.depth, "")
		_, _ = fmt.Fprintf(q.logw, format, args...)
	}
}

func (q *query) logResponse(rtt time.Duration, msg *dns.Msg, err error) {
	if q.logw != nil {
		if msg != nil {
			var elapsed string
			if rtt != 0 {
				elapsed = fmt.Sprintf("%v, ", rtt.Round(time.Millisecond))
			}
			fmt.Fprintf(q.logw, " => %s [%v+%v+%v A/N/E] (%s%d bytes",
				dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra),
				elapsed, msg.Len())
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
			fmt.Fprintf(q.logw, " ERROR: %v", err)
		}
		fmt.Fprintln(q.logw)
	}
}

func (q *query) exchange(ctx context.Context, qname string, qtype uint16, nsaddr netip.Addr) (resp *dns.Msg, err error) {
	if q.cache != nil {
		if resp = q.cache.DnsGet(qname, qtype); resp != nil {
			q.logf("CACHED: %s %q", dns.Type(qtype), qname)
			q.logResponse(0, resp, nil)
			return
		}
	}
	if q.usingUDP() {
		if resp, err = q.exchangeWithNetwork(ctx, "udp", qname, qtype, nsaddr); err != nil {
			if q.maybeDisableUdp(err) {
				err = nil
			}
		}
	}
	if err == nil && (resp == nil || resp.Truncated) {
		resp, err = q.exchangeWithNetwork(ctx, "tcp", qname, qtype, nsaddr)
	}
	if resp != nil && q.cache != nil {
		q.cache.DnsSet(resp)
	}
	return
}

func (q *query) exchangeWithNetwork(ctx context.Context, protocol string, qname string, qtype uint16, nsaddr netip.Addr) (msg *dns.Msg, err error) {
	if err = q.getUsable(ctx, protocol, nsaddr); err == nil {
		var network string
		if nsaddr.Is4() {
			network = protocol + "4"
		} else {
			network = protocol + "6"
		}

		if q.rateLimiter != nil {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				return
			case <-q.rateLimiter:
			}
		}

		if q.logw != nil {
			var protostr string
			var dash6str string
			if protocol != "udp" {
				protostr = " +" + protocol
			}
			if nsaddr.Is6() {
				dash6str = " -6"
			}
			q.logf("SENDING %s: @%s%s%s %s %q", network, nsaddr, protostr, dash6str, dns.Type(qtype), qname)
		}

		var nconn net.Conn
		var rtt time.Duration

		q.mu.RLock()
		if q.Timeout > 0 {
			ctx2, cancel := context.WithTimeout(ctx, q.Timeout)
			defer cancel()
			ctx = ctx2
		}
		clicookie := q.clicookie
		srvcookie, hasSrvCookie := q.getSrvCookieLocked(nsaddr)
		msgsize := q.MsgSize
		q.mu.RUnlock()

		if nconn, err = q.DialContext(ctx, network, netip.AddrPortFrom(nsaddr, q.DNSPort).String()); err == nil {
			dnsconn := &dns.Conn{Conn: nconn, UDPSize: msgsize}
			defer dnsconn.Close()

			m := new(dns.Msg)
			m.SetQuestion(qname, qtype)
			m.RecursionDesired = false
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetUDPSize(msgsize)

			// an existing but empty string for srvcookie means cookies are disabled for this server
			useCookies := !hasSrvCookie || srvcookie != ""
			if useCookies {
				opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
					Code:   dns.EDNS0COOKIE,
					Cookie: clicookie + srvcookie,
				})
				if hasSrvCookie && q.logw != nil {
					fmt.Fprintf(q.logw, " COOKIE:\"%s|%s\"", maskCookie(clicookie), maskCookie(srvcookie))
				}
			}

			m.Extra = append(m.Extra, opt)
			c := dns.Client{UDPSize: msgsize}
			msg, rtt, err = c.ExchangeWithConnContext(ctx, m, dnsconn)

			if useCookies && msg != nil {
				newsrvcookie := srvcookie
				if opt := msg.IsEdns0(); opt != nil {
					for _, rr := range opt.Option {
						switch rr := rr.(type) {
						case *dns.EDNS0_COOKIE:
							if after, ok := strings.CutPrefix(rr.Cookie, clicookie); ok {
								newsrvcookie = after
							} else {
								msg = nil
								err = ErrInvalidCookie
							}
						}
					}
				}
				if err == nil && newsrvcookie != "" {
					if !hasSrvCookie || srvcookie != newsrvcookie {
						if q.logw != nil {
							fmt.Fprintf(q.logw, " SETCOOKIE:\"%s\"", maskCookie(newsrvcookie))
						}
						q.setSrvCookie(q.start, nsaddr, newsrvcookie)
					}
				}
			}
		}

		isIpv6Err, isUdpErr := q.setNetError(protocol, nsaddr, err)
		ipv6disabled := isIpv6Err && q.maybeDisableIPv6(err)
		udpDisabled := isUdpErr && q.maybeDisableUdp(err)

		if q.logw != nil {
			if ipv6disabled {
				fmt.Fprintf(q.logw, " (IPv6 disabled)")
			}
			if udpDisabled {
				fmt.Fprintf(q.logw, " (UDP disabled)")
			}
			q.logResponse(rtt, msg, err)
		}

		if !hasSrvCookie && msg != nil && msg.Rcode == dns.RcodeFormatError {
			q.logf("got FORMERR, disabling cookies for %v and retrying\n", nsaddr)
			q.setSrvCookie(q.start, nsaddr, "")
			return q.exchangeWithNetwork(ctx, protocol, qname, qtype, nsaddr)
		}
	}
	return
}

func (r *Recursive) getUsable(ctx context.Context, protocol string, nsaddr netip.Addr) (err error) {
	if err = ctx.Err(); err == nil {
		var m map[netip.Addr]netError
		switch protocol {
		case "udp", "udp4", "udp6":
			m = r.udperrs
		case "tcp", "tcp4", "tcp6":
			m = r.tcperrs
		}
		err = net.ErrClosed
		if m != nil {
			r.mu.RLock()
			ne, hasNetError := m[nsaddr]
			if !hasNetError {
				if (r.useIPv4 && nsaddr.Is4()) || (r.useIPv6 && nsaddr.Is6()) {
					err = nil
				}
			}
			r.mu.RUnlock()
			if hasNetError {
				err = ne
				if time.Since(ne.When) > time.Minute {
					err = nil
					r.mu.Lock()
					delete(m, nsaddr)
					r.mu.Unlock()
				}
			}
		}
	}
	return
}

func (r *Recursive) sortAddrs(in []netip.Addr) []netip.Addr {
	if r.Deterministic {
		sort.Slice(in, func(i, j int) bool { return in[i].Compare(in[j]) < 0 })
	} else {
		rand.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
	}
	return in
}

func cnameTarget(resp *dns.Msg, owner string) (tgt string) {
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, owner) {
			tgt = dns.CanonicalName(c.Target)
		}
	}
	return
}

// dnameSynthesize finds a DNAME and synthesizes the new qname per RFC 6672.
func dnameSynthesize(resp *dns.Msg, qname string) (tgt string) {
	q := strings.ToLower(qname)
	for _, rr := range resp.Answer {
		if d, ok := rr.(*dns.DNAME); ok {
			owner := strings.ToLower(d.Hdr.Name)
			if strings.HasSuffix(q, owner) {
				prefix := strings.TrimSuffix(q, owner)
				// Avoid double dots when concatenating
				prefix = strings.TrimSuffix(prefix, ".")
				tgt = dns.CanonicalName(strings.Trim(prefix, ".") + "." + d.Target)
				break
			}
		}
	}
	return
}

func hasRRType(rrs []dns.RR, t uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}

func delegationRecords(m *dns.Msg, zone string) (out []dns.RR) {
	if m != nil {
		for _, rr := range m.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				if strings.EqualFold(ns.Hdr.Name, zone) {
					out = append(out, rr)
				}
			}
		}
	}
	return
}
func cnameChainRecords(rrs []dns.RR, owner string) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if cname, ok := rr.(*dns.CNAME); ok {
			if strings.EqualFold(cname.Hdr.Name, owner) {
				out = append(out, rr)
			}
		}
	}
	return out
}

func dnameRecords(rrs []dns.RR, qname string) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if d, ok := rr.(*dns.DNAME); ok {
			if strings.HasSuffix(strings.ToLower(qname), strings.ToLower(d.Hdr.Name)) {
				out = append(out, rr)
			}
		}
		if cname, ok := rr.(*dns.CNAME); ok {
			if strings.EqualFold(cname.Hdr.Name, qname) {
				out = append(out, rr)
			}
		}
	}
	return out
}

func prependRecords(msg *dns.Msg, resp *dns.Msg, qname string, gather func([]dns.RR, string) []dns.RR) {
	records := gather(resp.Answer, qname)
	if len(msg.Question) > 0 {
		msg.Question[0].Name = qname
	}
	if len(records) > 0 {
		msg.Answer = append(append([]dns.RR(nil), records...), msg.Answer...)
	}
	if len(msg.Ns) == 0 {
		if len(resp.Ns) > 0 {
			msg.Ns = append([]dns.RR(nil), resp.Ns...)
		}
	}
	if len(resp.Extra) > 0 {
		extras := append([]dns.RR(nil), resp.Extra...)
		msg.Extra = append(extras, msg.Extra...)
	}
}

func ipToAddr(ip net.IP) (addr netip.Addr) {
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			addr = netip.AddrFrom4([4]byte(v4))
		} else if v6 := ip.To16(); v6 != nil {
			addr = netip.AddrFrom16([16]byte(v6))
		}
	}
	return
}

func cloneIfCached(msg *dns.Msg) (clone *dns.Msg) {
	clone = msg
	if msg.Zero {
		clone = msg.Copy()
		clone.Zero = false
	}
	return
}
