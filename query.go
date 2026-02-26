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
		err = ErrMaxDepth
		if q.depth < maxDepth {
			q.steps++
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
	if servers, resp, srv, err = q.queryDelegation(ctx, qname); err == nil {
		if resp != nil && resp.Rcode == dns.RcodeNameError {
			// no need to query final
			if len(resp.Question) == 1 && (dns.CanonicalName(resp.Question[0].Name) != qname || resp.Question[0].Qtype != qtype) {
				if resp.Zero {
					resp = resp.Copy()
					resp.Zero = false
				}
				resp.Question[0].Name = qname
				resp.Question[0].Qtype = qtype
			}
		} else {
			resp, srv, err = q.queryFinal(ctx, qname, qtype, servers)
		}
	}
	return
}

func (q *query) using() (using []string) {
	if q.logw != nil {
		q.mu.RLock()
		if q.useIPv4 {
			using = append(using, "IPv4")
		}
		if q.useIPv6 {
			using = append(using, "IPv6")
		}
		if q.useUDP {
			using = append(using, "UDP")
		}
		q.mu.RUnlock()
	}
	return
}

func (q *query) queryDelegation(ctx context.Context, qname string) (servers []netip.Addr, resp *dns.Msg, srv netip.Addr, err error) {
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

		q.mu.RLock()
		servers = append([]netip.Addr(nil), q.rootServers...)
		q.mu.RUnlock()
		labels := dns.SplitDomainName(qname)

		// Walk down: "." -> "com." -> "example.com."
		for i := len(labels) - 1; i >= 0; i-- {
			zone := dns.Fqdn(strings.Join(labels[i:], "."))
			var nsAddrs []netip.Addr

			if nsAddrs, resp, srv, err = q.queryForDelegation(ctx, zone, servers, qname); err != nil {
				q.logf("DELEGATION ERROR %q: @%s %v (using %v)\n", zone, srv, err, q.using())
				return
			}
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				if len(resp.Question) == 1 && dns.CanonicalName(resp.Question[0].Name) == qname {
					return
				}
			}

			if len(nsAddrs) > 0 {
				// got a new set of servers to query
				servers = q.sortAddrs(nsAddrs)
				if i == 0 {
					// If the final minimized step returned a delegation, probe the delegated NS set once.
					// This ensures delegation lookup does not stop before querying the final NS servers.
					var probeResp *dns.Msg
					var probeSrv netip.Addr
					var probeErr error
					if _, probeResp, probeSrv, probeErr = q.queryForDelegationWithCachePolicy(ctx, qname, servers, qname, isAuthoritativeCacheResponse); probeErr == nil {
						if probeResp != nil {
							resp = probeResp
							srv = probeSrv
						}
					}
				}
			}
		}
	}
	return
}

// queryForDelegation performs the QMIN step at `zone` against `parentServers`.
func (q *query) queryForDelegation(ctx context.Context, zone string, parentServers []netip.Addr, fullQname string) (nsAddrs []netip.Addr, resp *dns.Msg, srv netip.Addr, err error) {
	return q.queryForDelegationWithCachePolicy(ctx, zone, parentServers, fullQname, nil)
}

func (q *query) queryForDelegationWithCachePolicy(ctx context.Context, zone string, parentServers []netip.Addr, fullQname string, allowCached func(*dns.Msg) bool) (nsAddrs []netip.Addr, resp *dns.Msg, srv netip.Addr, err error) {
	var nsNames []string
	queryName := zone
	maybeRetryWithoutQMIN := func() (yes bool) {
		if yes = queryName != fullQname; yes {
			q.logf("DELEGATION RETRY without QNAME minimization\n")
			queryName = fullQname
		}
		return
	}
retryWithoutQMIN:
	for _, srv = range parentServers {
		if resp, err = q.exchangeWithCachePolicy(ctx, queryName, dns.TypeNS, srv, allowCached); resp != nil && err == nil {
			if resp.Rcode == dns.RcodeSuccess {
				nsNames, nsAddrs = q.extractDelegationNS(resp, zone)
				if len(nsNames) > 0 {
					var missingNS []string
					missingNS = q.missingNSAddrs(nsNames)
					if len(missingNS) > 0 {
						nsAddrs = appendUniqueAddrs(nsAddrs, q.resolveNSAddrs(ctx, missingNS))
					}
				}
				if len(nsAddrs) > 0 {
					return
				}
				if resp.Authoritative && len(nsNames) == 0 {
					if maybeRetryWithoutQMIN() {
						goto retryWithoutQMIN
					}
					return
				}
			}
			if resp.Rcode != dns.RcodeSuccess {
				if maybeRetryWithoutQMIN() {
					goto retryWithoutQMIN
				}
				if resp.Rcode == dns.RcodeNameError && resp.Authoritative {
					return
				}
			}
		}
	}

	if resp == nil && err == nil {
		err = ErrNoResponse
	}

	return
}

func (q *query) extractDelegationNS(m *dns.Msg, zone string) (nsNames []string, nsAddr []netip.Addr) {
	var useIPv4 bool
	var useIPv6 bool
	useIPv4, useIPv6 = q.nsAddressFamilies()

	// Extract NS records naming the next zone servers from both authority
	// (delegation) and answer (authoritative NS response) sections.
	nsNames = appendZoneNSNames(nsNames, m.Ns, zone)
	nsNames = appendZoneNSNames(nsNames, m.Answer, zone)
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
	// Build one preferred address per nameserver owner. Keeping every
	// address can create an oversized list of candidate servers.
	for _, nsName := range nsNames {
		var addr netip.Addr
		addr = pickPreferredNSAddr(q.glue[nsName], useIPv4, useIPv6)
		if addr.IsValid() {
			if !slices.Contains(nsAddr, addr) {
				nsAddr = append(nsAddr, addr)
			}
		}
	}
	return
}

func appendZoneNSNames(dst []string, records []dns.RR, zone string) (out []string) {
	out = dst
	for _, rr := range records {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.EqualFold(ns.Hdr.Name, zone) {
				nsName := dns.CanonicalName(ns.Ns)
				if !slices.Contains(out, nsName) {
					out = append(out, nsName)
				}
			}
		}
	}
	return
}

func appendUniqueAddrs(dst []netip.Addr, src []netip.Addr) (out []netip.Addr) {
	out = dst
	for _, addr := range src {
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	return
}

func (q *query) missingNSAddrs(nsNames []string) (missing []string) {
	var useIPv4 bool
	var useIPv6 bool
	useIPv4, useIPv6 = q.nsAddressFamilies()
	for _, nsName := range nsNames {
		if !pickPreferredNSAddr(q.glue[nsName], useIPv4, useIPv6).IsValid() {
			missing = append(missing, nsName)
		}
	}
	return
}

// queryFinal asks the authoritative (or closest) servers for the target qname/qtype.
// It also performs CNAME/DNAME chasing, with a loop bound controlled by depth.
func (q *query) queryFinal(ctx context.Context, qname string, qtype uint16, authServers []netip.Addr) (resp *dns.Msg, svr netip.Addr, err error) {
	if err = q.dive("QUERY %s %q from %d servers\n", dns.Type(qtype), qname, len(authServers)); err == nil {
		var aliasFallback *dns.Msg
		var aliasFallbackServer netip.Addr
		defer func() {
			q.surface()
			q.logf("ANSWER @%s %s %q", svr, dns.Type(qtype), qname)
			q.logResponse(0, resp, err)
		}()
		for _, svr = range authServers {
			if resp, err = q.exchangeWithCachePolicy(ctx, qname, qtype, svr, isAuthoritativeCacheResponse); resp != nil && err == nil {
				if resp.Rcode == dns.RcodeSuccess {
					terminal := hasRRType(resp.Answer, qtype)
					if !terminal {
						if tgt := cnameTarget(resp, qname); tgt != "" {
							q.logf("CNAME @%s %s %q => %q\n", svr, dns.Type(qtype), qname, tgt)
							var msg *dns.Msg
							var origin netip.Addr
							msg, origin, err = q.resolve(ctx, tgt, qtype)
							if err == nil {
								msg = cloneIfCached(msg)
								prependRecords(msg, resp, qname, dnameRecords)
								resp = msg
								svr = origin
								terminal = true
							} else {
								if aliasFallback == nil {
									aliasFallback = cloneIfCached(resp)
									aliasFallbackServer = svr
								}
								resp = nil
								err = nil
								continue
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
								terminal = true
							} else {
								if aliasFallback == nil {
									aliasFallback = cloneIfCached(resp)
									aliasFallbackServer = svr
								}
								resp = nil
								err = nil
								continue
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
								terminal = true
							}
						}
						if !terminal && !resp.Authoritative {
							resp = nil
							continue
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

		if err == nil {
			if aliasFallback != nil {
				if resp == nil || resp.Rcode != dns.RcodeSuccess {
					resp = aliasFallback
					svr = aliasFallbackServer
				}
			}
			if resp == nil {
				err = ErrNoResponse
			}
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

		var useIPv4 bool
		var useIPv6 bool
		useIPv4, useIPv6 = q.nsAddressFamilies()

		for _, host := range nsOwners {
			var hostAddrs []netip.Addr
			if useIPv4 {
				if msg, _, err := q.resolve(ctx, host, dns.TypeA); err == nil {
					var addr netip.Addr
					addr = firstResolvedAddr(msg, host, dns.TypeA)
					if addr.IsValid() {
						hostAddrs = append(hostAddrs, addr)
					}
				}
			}
			if useIPv6 {
				if msg, _, err := q.resolve(ctx, host, dns.TypeAAAA); err == nil {
					var addr netip.Addr
					addr = firstResolvedAddr(msg, host, dns.TypeAAAA)
					if addr.IsValid() {
						hostAddrs = append(hostAddrs, addr)
					}
				}
			}
			var addr netip.Addr
			addr = pickPreferredNSAddr(hostAddrs, useIPv4, useIPv6)
			if addr.IsValid() {
				if !slices.Contains(addrs, addr) {
					addrs = append(addrs, addr)
				}
			}
		}
	}
	return
}

func (q *query) nsAddressFamilies() (useIPv4 bool, useIPv6 bool) {
	q.mu.RLock()
	useIPv4 = q.useIPv4
	useIPv6 = q.useIPv6
	q.mu.RUnlock()
	return
}

func pickPreferredNSAddr(candidates []netip.Addr, useIPv4 bool, useIPv6 bool) (addr netip.Addr) {
	if useIPv4 {
		for _, candidate := range candidates {
			if candidate.Is4() {
				addr = candidate
				break
			}
		}
	}
	if !addr.IsValid() {
		if useIPv6 {
			for _, candidate := range candidates {
				if candidate.Is6() {
					addr = candidate
					break
				}
			}
		}
	}
	return
}

func firstResolvedAddr(msg *dns.Msg, owner string, rrtype uint16) (addr netip.Addr) {
	owner = dns.CanonicalName(owner)
	if msg != nil {
		// Prefer records that match the requested owner directly.
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype == rrtype {
				if strings.EqualFold(rr.Header().Name, owner) {
					addr = addrFromRR(rr)
					if addr.IsValid() {
						return
					}
				}
			}
		}
		// Fallback for responses that only contain target records (e.g. via CNAME).
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype == rrtype {
				addr = addrFromRR(rr)
				if addr.IsValid() {
					break
				}
			}
		}
	}
	return
}

func addrFromRR(rr dns.RR) (addr netip.Addr) {
	switch typed := rr.(type) {
	case *dns.A:
		addr = ipToAddr(typed.A)
	case *dns.AAAA:
		addr = ipToAddr(typed.AAAA)
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
			_, _ = fmt.Fprintf(q.logw, " => %s [%v+%v+%v A/N/E] (%s%d bytes",
				dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra),
				elapsed, msg.Len())
			if msg.Truncated {
				_, _ = fmt.Fprintf(q.logw, " TRNC")
			}
			if msg.Authoritative {
				_, _ = fmt.Fprintf(q.logw, " AUTH")
			}
			if opt := msg.IsEdns0(); opt != nil {
				if er := uint16(opt.ExtendedRcode()); /*#nosec G115*/ er != 0 {
					_, _ = fmt.Fprintf(q.logw, " EDNS=%s", dns.ExtendedErrorCodeToString[er])
				}
			}
			_, _ = fmt.Fprintf(q.logw, ")")
		}
		if err != nil {
			_, _ = fmt.Fprintf(q.logw, " ERROR: %v", err)
		}
		_, _ = fmt.Fprintln(q.logw)
	}
}

func (q *query) exchange(ctx context.Context, qname string, qtype uint16, nsaddr netip.Addr) (resp *dns.Msg, err error) {
	resp, err = q.exchangeWithCachePolicy(ctx, qname, qtype, nsaddr, nil)
	return
}

func (q *query) exchangeWithCachePolicy(ctx context.Context, qname string, qtype uint16, nsaddr netip.Addr, allowCached func(*dns.Msg) bool) (resp *dns.Msg, err error) {
	if q.cache != nil {
		if resp = q.cache.DnsGet(qname, qtype); resp != nil {
			if allowCached == nil || allowCached(resp) {
				q.logf("CACHED: %s %q", dns.Type(qtype), qname)
				q.logResponse(0, resp, nil)
				return
			}
			resp = nil
		}
	}
	q.mu.RLock()
	useUDP := q.useUDP
	useIPv4 := q.useIPv4
	useIPv6 := q.useIPv6
	q.mu.RUnlock()
	if (useIPv4 && nsaddr.Is4()) || (useIPv6 && nsaddr.Is6()) {
		if useUDP {
			resp, _ = q.exchangeWithNetwork(ctx, "udp", qname, qtype, nsaddr)
		}
		if resp == nil || resp.Truncated {
			resp, err = q.exchangeWithNetwork(ctx, "tcp", qname, qtype, nsaddr)
		}
		if resp != nil && q.cache != nil && isReusableCachedResponse(resp, qtype) {
			q.cache.DnsSet(resp)
		}
	}
	return
}

func isAuthoritativeCacheResponse(resp *dns.Msg) (ok bool) {
	if resp != nil {
		ok = resp.Authoritative
	}
	return
}

func isReusableCachedResponse(resp *dns.Msg, qtype uint16) (ok bool) {
	if resp != nil && !resp.Truncated {
		ok = resp.Rcode == dns.RcodeNameError && resp.Authoritative
		if resp.Rcode == dns.RcodeSuccess {
			ok = true
			if qtype == dns.TypeNS {
				ok = hasQuestionNSRecord(resp)
			}
		}
	}
	return
}

func hasQuestionNSRecord(resp *dns.Msg) (ok bool) {
	if resp != nil && len(resp.Question) == 1 {
		qname := dns.CanonicalName(resp.Question[0].Name)
		for _, rr := range resp.Answer {
			if ns, yes := rr.(*dns.NS); yes && strings.EqualFold(ns.Hdr.Name, qname) {
				ok = true
				break
			}
		}
		if !ok {
			for _, rr := range resp.Ns {
				if ns, yes := rr.(*dns.NS); yes && strings.EqualFold(ns.Hdr.Name, qname) {
					ok = true
					break
				}
			}
		}
	}
	return
}

func (q *query) exchangeWithNetwork(ctx context.Context, protocol string, qname string, qtype uint16, nsaddr netip.Addr) (msg *dns.Msg, err error) {
	if err = q.getCachedNetError(ctx, protocol, nsaddr); err == nil {
		maxCookieRetries := 1
		for attempt := 0; attempt <= maxCookieRetries; attempt++ {
			msg = nil
			err = nil
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
			timeout := q.Timeout
			clicookie := q.clicookie
			srvcookie, hasSrvCookie := q.getSrvCookieLocked(nsaddr)
			msgsize := q.MsgSize
			q.mu.RUnlock()

			reqctx := ctx
			var cancel context.CancelFunc
			if timeout > 0 {
				reqctx, cancel = context.WithTimeout(ctx, timeout)
			}

			useCookies := !hasSrvCookie || srvcookie != ""
			if nconn, err = q.DialContext(reqctx, network, netip.AddrPortFrom(nsaddr, q.DNSPort).String()); err == nil {
				dnsconn := &dns.Conn{Conn: nconn, UDPSize: msgsize}
				defer func() { _ = dnsconn.Close() }()

				m := new(dns.Msg)
				m.SetQuestion(qname, qtype)
				m.RecursionDesired = false
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetUDPSize(msgsize)
				if queryNeedsDO(qtype) {
					opt.SetDo()
				}

				// an existing but empty string for srvcookie means cookies are disabled for this server
				if useCookies {
					opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
						Code:   dns.EDNS0COOKIE,
						Cookie: clicookie + srvcookie,
					})
					if hasSrvCookie && q.logw != nil {
						_, _ = fmt.Fprintf(q.logw, " COOKIE:\"%s|%s\"", maskCookie(clicookie), maskCookie(srvcookie))
					}
				}

				m.Extra = append(m.Extra, opt)
				c := dns.Client{UDPSize: msgsize}
				var rawmsg *dns.Msg
				if rawmsg, rtt, err = c.ExchangeWithConnContext(reqctx, m, dnsconn); err == nil {
					if msg, err = validateResponseQuestion(rawmsg, qname, qtype); err == nil {
						if useCookies {
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
										_, _ = fmt.Fprintf(q.logw, " SETCOOKIE:\"%s\"", maskCookie(newsrvcookie))
									}
									q.setSrvCookie(q.start, nsaddr, newsrvcookie)
								}
							}
						}
					}
				}
			}
			if cancel != nil {
				cancel()
			}

			isIpv6Err, isUdpErr := q.setNetError(protocol, nsaddr, err)
			ipv6disabled := isIpv6Err && q.maybeDisableIPv6(err)
			udpDisabled := isUdpErr && q.maybeDisableUdp(err)

			if q.logw != nil {
				if ipv6disabled {
					_, _ = fmt.Fprintf(q.logw, " (IPv6 disabled)")
				}
				if udpDisabled {
					_, _ = fmt.Fprintf(q.logw, " (UDP disabled)")
				}
				q.logResponse(rtt, msg, err)
			}

			retry := false
			if !hasSrvCookie && msg != nil && msg.Rcode == dns.RcodeFormatError {
				q.logf("got FORMERR, disabling cookies for %v and retrying\n", nsaddr)
				q.setSrvCookie(q.start, nsaddr, "")
				retry = true
			}
			if msg != nil && msg.Rcode == dns.RcodeBadCookie {
				if useCookies {
					q.logf("got BADCOOKIE, retrying with refreshed cookie for %v\n", nsaddr)
					retry = true
				}
			}
			if !retry || attempt >= maxCookieRetries {
				break
			}
		}
	}
	return
}

func (r *Recursive) getCachedNetError(ctx context.Context, protocol string, nsaddr netip.Addr) (err error) {
	if err = ctx.Err(); err == nil {
		var m map[netip.Addr]*CachedNetError
		switch protocol {
		case "udp", "udp4", "udp6":
			m = r.udperrs
		case "tcp", "tcp4", "tcp6":
			m = r.tcperrs
		}
		if m != nil {
			r.mu.RLock()
			ne := m[nsaddr]
			r.mu.RUnlock()
			if ne != nil {
				if time.Since(ne.When) < time.Minute {
					err = ne
				} else {
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
	for _, rr := range resp.Answer {
		if d, ok := rr.(*dns.DNAME); ok {
			if before, ok0 := cutDomainSuffix(qname, d.Hdr.Name); ok0 {
				prefix := before
				// Avoid double dots when concatenating
				prefix = strings.TrimSuffix(prefix, ".")
				candidate := d.Target
				if prefix != "" {
					candidate = strings.Trim(prefix, ".") + "." + d.Target
				}
				tgt = dns.CanonicalName(candidate)
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

func queryNeedsDO(qtype uint16) (needs bool) {
	switch qtype {
	case dns.TypeDS:
		needs = true
	case dns.TypeDNSKEY:
		needs = true
	case dns.TypeRRSIG:
		needs = true
	case dns.TypeNSEC:
		needs = true
	case dns.TypeNSEC3:
		needs = true
	case dns.TypeNSEC3PARAM:
		needs = true
	case dns.TypeCDS:
		needs = true
	case dns.TypeCDNSKEY:
		needs = true
	}
	return
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
			if _, match := cutDomainSuffix(qname, d.Hdr.Name); match {
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

func cutDomainSuffix(name, suffix string) (before string, ok bool) {
	name = strings.ToLower(dns.CanonicalName(name))
	suffix = strings.ToLower(dns.CanonicalName(suffix))
	if before, ok = strings.CutSuffix(name, suffix); ok {
		ok = before == "" || strings.HasSuffix(before, ".")
	}
	return
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
		var extras []dns.RR
		for _, rr := range resp.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				extras = append(extras, rr)
			}
		}
		if len(extras) > 0 {
			msg.Extra = append(extras, msg.Extra...)
		}
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

func validateResponseQuestion(msg *dns.Msg, qname string, qtype uint16) (outmsg *dns.Msg, err error) {
	mismatchedQuestionErr := &MismatchedQuestionError{
		ExpectedQName: dns.CanonicalName(qname),
		ExpectedQType: qtype,
	}
	err = mismatchedQuestionErr
	if msg != nil {
		if len(msg.Question) > 0 {
			q := msg.Question[0]
			mismatchedQuestionErr.ActualQName = dns.CanonicalName(q.Name)
			mismatchedQuestionErr.ActualQType = q.Qtype
			if len(msg.Question) == 1 {
				if mismatchedQuestionErr.ActualQName == mismatchedQuestionErr.ExpectedQName {
					if mismatchedQuestionErr.ActualQType == mismatchedQuestionErr.ExpectedQType && q.Qclass == dns.ClassINET {
						err = nil
						outmsg = msg
					}
				}
			}
		}
	}
	return
}
