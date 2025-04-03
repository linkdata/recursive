package recursive

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

/*
	Good tests:
	NS	google.tw.cn.
	NS	bankgirot.nu.
	NS	skandia.com.ci.
	A	m.hkirc.net.hk.
	A	www.microsoft.com.
	A   console.aws.amazon.com.
	A   *.en.se.
	A	teli.se.
	A	telia.biz.mv.
	A	telia.per.la.
	NS	seb.inf.ua
	A	seb.org.tw
*/

//go:generate go run ./cmd/genhints roothints.gen.go

const (
	maxDepth        = 64 // maximum recursion depth
	maxRootAttempts = 2  // maximum number of root servers to try
)

var (
	// ErrMaxDepth is returned when recursive resolving exceeds the allowed limit.
	ErrMaxDepth = fmt.Errorf("recursion depth exceeded %d", maxDepth)
	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	// It is equivalent to SERVFAIL.
	ErrNoResponse = errors.New("no authoritative response")
	errEmptyNS    = errors.New("ignoring non-auth empty NS")
	DefaultCache  = NewCache()
)

var _ Resolver = (*Recursive)(nil) // ensure we implement interface

type netError struct {
	Err  error
	When time.Time
}

func (ne netError) Error() string {
	return ne.Err.Error()
}

func (ne netError) Unwrap() error {
	return ne.Err
}

var DefaultTimeout = time.Second * 5

type Recursive struct {
	proxy.ContextDialer                 // (read-only) ContextDialer passed to NewWithOptions
	Cacher                              // (read-only) Cacher passed to NewWithOptions
	*net.Resolver                       // (read-only) net.Resolver using our ContextDialer
	Timeout             time.Duration   // (read-only) dialing timeout, zero to disable
	rateLimiter         <-chan struct{} // (read-only) rate limited passed to NewWithOptions
	DefaultLogWriter    io.Writer       // if not nil, write debug logs here unless overridden
	NoMini              bool            // don't use QNAME minimization
	mu                  sync.RWMutex    // protects following
	useUDP              bool
	useIPv4             bool
	useIPv6             bool
	rootServers         []netip.Addr
	cookiernd           uint64
	srvcookies          map[netip.Addr]string
	udperrs             map[netip.Addr]netError
	tcperrs             map[netip.Addr]netError
}

// NewWithOptions returns a new Recursive resolver using the given ContextDialer and
// using the given Cacher as it's default cache. It does not call OrderRoots.
//
// Passing nil for dialer will use a net.Dialer.
// Passing nil for cache means it won't use any cache by default.
// Passing nil for the roots will use the default set of roots.
// Passing nil for the rateLimiter means no rate limiting
func NewWithOptions(dialer proxy.ContextDialer, cache Cacher, roots4, roots6 []netip.Addr, rateLimiter <-chan struct{}) *Recursive {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	if roots4 == nil {
		roots4 = Roots4
	}
	if roots6 == nil {
		roots6 = Roots6
	}

	var root4, root6 []netip.Addr
	if len(roots4) > 0 {
		root4 = append(root4, roots4...)
		rand.Shuffle(len(root4), func(i, j int) { root4[i], root4[j] = root4[j], root4[i] })
	}
	if len(roots6) > 0 {
		root6 = append(root6, roots6...)
		rand.Shuffle(len(root6), func(i, j int) { root6[i], root6[j] = root6[j], root6[i] })
	}

	roots := make([]netip.Addr, 0, len(root4)+len(root6))
	n := min(len(root4), len(root6))
	for i := 0; i < n; i++ {
		roots = append(roots, root4[i], root6[i])
	}
	roots = append(roots, root4[n:]...)
	roots = append(roots, root6[n:]...)

	return &Recursive{
		ContextDialer: dialer,
		Cacher:        cache,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     dialer.DialContext,
		},
		Timeout:     DefaultTimeout,
		rateLimiter: rateLimiter,
		useUDP:      true,
		useIPv4:     len(root4) > 0,
		useIPv6:     len(root6) > 0,
		rootServers: roots,
		cookiernd:   rand.Uint64(),
		srvcookies:  make(map[netip.Addr]string),
		udperrs:     make(map[netip.Addr]netError),
		tcperrs:     make(map[netip.Addr]netError),
	}
}

// New returns a new Recursive resolver using the given ContextDialer and
// has DefaultCache as it's cache.
//
// It calls OrderRoots before returning.
func New(dialer proxy.ContextDialer) *Recursive {
	r := NewWithOptions(dialer, DefaultCache, nil, nil, nil)
	r.OrderRoots(context.Background())
	return r
}

// ResetCookies generates a new DNS client cookie and clears the known DNS server cookies.
func (r *Recursive) ResetCookies() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cookiernd = rand.Uint64()
	clear(r.srvcookies)
}

// OrderRoots sorts the root server list by their current latency and removes those that don't respond.
//
// If ctx does not have a deadline, a deadline of five seconds will be used.
func (r *Recursive) OrderRoots(ctx context.Context) {
	if _, ok := ctx.Deadline(); !ok {
		newctx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		ctx = newctx
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var l []*rootRtt
	var wg sync.WaitGroup
	for _, addr := range r.rootServers {
		rt := &rootRtt{addr: addr}
		l = append(l, rt)
		wg.Add(1)
		go timeRoot(ctx, r, &wg, rt)
	}
	wg.Wait()
	sort.Slice(l, func(i, j int) bool { return l[i].rtt < l[j].rtt })
	var newRootServers []netip.Addr
	useIPv4 := false
	useIPv6 := false
	for _, rt := range l {
		if rt.rtt < time.Minute {
			useIPv4 = useIPv4 || rt.addr.Is4()
			useIPv6 = useIPv6 || rt.addr.Is6()
			newRootServers = append(newRootServers, rt.addr)
		}
	}
	if len(newRootServers) > 0 {
		r.rootServers = newRootServers
		r.useIPv4 = useIPv4
		r.useIPv6 = useIPv6
	}
}

type initialQuery struct {
	nsaddr netip.Addr
	qname  string
	qtype  uint16
	nomini bool
}

type state struct {
	ctx    context.Context
	start  time.Time
	cache  Cacher
	logw   io.Writer
	depth  int
	nsaddr netip.Addr
	qname  string
	qtype  uint16
	qlabel int
	nomini bool
	stack  map[initialQuery]struct{}
}

// ResolveWithOptions will perform a recursive DNS resolution for the provided name and record type,
// and if logw is non-nil (or DefaultLogWriter is set), write a log of events.
func (r *Recursive) ResolveWithOptions(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	if logw == nil {
		logw = r.DefaultLogWriter
	}
	if false {
		msg, srv, err = r.runQuery(ctx, cache, logw, qname, qtype)
	} else {
		start := time.Now()
		qname = dns.CanonicalName(qname)
		if _, ok := dns.IsDomainName(qname); !ok {
			return nil, netip.Addr{}, dns.ErrRdata
		}
		s := state{
			ctx:    ctx,
			start:  start,
			cache:  cache,
			logw:   logw,
			depth:  0,
			nsaddr: netip.Addr{},
			qname:  qname,
			qtype:  qtype,
			qlabel: 0,
			nomini: r.NoMini,
			stack:  make(map[initialQuery]struct{}),
		}
		msg, srv, err := r.recurseFromRoot(s)
		if logw != nil {
			if msg != nil {
				fmt.Fprintf(logw, "\n%v", msg)
			}
			fmt.Fprintf(logw, "\n;; Query time: %v\n;; SERVER: %v\n", time.Since(start).Round(time.Millisecond), srv)
			if err != nil {
				fmt.Fprintf(logw, ";; ERROR: %v\n", err)
			}
		}
		return msg, srv, err
	}
	return
}

// Resolve will perform a recursive DNS resolution for the provided name and record type.
func (r *Recursive) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return r.ResolveWithOptions(ctx, r, nil, qname, qtype)
}

// Roots returns the current set of root servers in use.
func (r *Recursive) GetRoots() (root4, root6 []netip.Addr) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, addr := range r.rootServers {
		if addr.Is4() {
			root4 = append(root4, addr)
		}
		if addr.Is6() {
			root6 = append(root6, addr)
		}
	}
	return
}

func (r *Recursive) nextRoot(i int) (addr netip.Addr) {
	r.mu.RLock()
	if l := len(r.rootServers); l > 0 {
		addr = r.rootServers[i%l]
	}
	r.mu.RUnlock()
	return
}

func (s *state) dbg() bool {
	return s.logw != nil
}

func (s *state) log(format string, args ...any) bool {
	fmt.Fprintf(s.logw, "[%-5d %2d] %*s", time.Since(s.start).Milliseconds(), s.depth, s.depth, "")
	fmt.Fprintf(s.logw, format, args...)
	return false
}

func (r *Recursive) recurseFromRoot(s state) (msg *dns.Msg, srv netip.Addr, err error) {
	s.qlabel = 1
	for i := 0; i < maxRootAttempts; i++ {
		if err = s.ctx.Err(); err != nil {
			return
		}
		if server := r.nextRoot(i); server.IsValid() {
			s.nsaddr = server
			rq := initialQuery{
				nsaddr: s.nsaddr,
				qname:  s.qname,
				qtype:  s.qtype,
				nomini: s.nomini,
			}
			if _, ok := s.stack[rq]; !ok {
				_ = s.dbg() && s.log("resolving from root @%v %s %q\n", s.nsaddr.String(), DnsTypeToString(s.qtype), s.qname)
				s.stack[rq] = struct{}{}
				msg, srv, err = r.recurse(s)
				delete(s.stack, rq)
				if s.errorTerminates(err) {
					return
				}
			} else {
				_ = s.dbg() && s.log("LOOP detected @%v %s %q\n", s.nsaddr.String(), DnsTypeToString(s.qtype), s.qname)
				err = ErrMaxDepth
				return
			}
		}
	}
	return
}

func (r *Recursive) usingUDP() (yes bool) {
	r.mu.RLock()
	yes = r.useUDP
	r.mu.RUnlock()
	return
}

func mustUseable(ctx context.Context, useIPv4, useIPv6 bool, protocol string, addr netip.Addr) (err error) {
	if err = ctx.Err(); err == nil {
		if (useIPv4 && addr.Is4()) || (useIPv6 && addr.Is6()) {
			return
		}
	}
	return net.ErrClosed
}

func (r *Recursive) useable(addr netip.Addr) (ok bool) {
	r.mu.RLock()
	ok = (r.useIPv4 && addr.Is4()) || (r.useIPv6 && addr.Is6())
	r.mu.RUnlock()
	return
}

func (r *Recursive) authQtypes() (qtypes []uint16) {
	r.mu.RLock()
	if r.useIPv4 {
		qtypes = append(qtypes, dns.TypeA)
	}
	if r.useIPv6 {
		qtypes = append(qtypes, dns.TypeAAAA)
	}
	r.mu.RUnlock()
	return
}

func answerTerminates(ans *dns.Msg) bool {
	return ans.Authoritative || ans.Rcode != dns.RcodeServerFailure
}

func (s *state) errorTerminates(err error) bool {
	switch {
	case err == nil:
	case err == dns.ErrRdata:
	case errors.Is(err, ErrNoResponse):
	case errors.Is(err, ErrMaxDepth):
	case s.ctx.Err() != nil:
	default:
		return false
	}
	return true
}

func (r *Recursive) recurse(s state) (*dns.Msg, netip.Addr, error) {
	if s.depth >= maxDepth {
		_ = s.dbg() && s.log("maximum depth reached\n")
		return nil, netip.Addr{}, ErrMaxDepth
	}

	qname := s.qname
	qtype := s.qtype

	idx, final := dns.PrevLabel(qname, s.qlabel)
	if !final && !s.nomini {
		qtype = dns.TypeNS
		qname = qname[idx:]
	}

	s2 := s
	s2.qname = qname
	s2.qtype = qtype
	resp, err := r.sendQuery(s2)
	if err != nil {
		return nil, s.nsaddr, err
	}

	var cnames []string
	var answer []dns.RR
	for _, rr := range resp.Answer {
		if crec, ok := rr.(*dns.CNAME); ok {
			switch qtype {
			case dns.TypeNS, dns.TypeMX:
				// not allowed
				continue
			case dns.TypeCNAME:
				// goes into answer
			default:
				cnames = append(cnames, dns.CanonicalName(crec.Target))
				continue
			}
		}
		answer = append(answer, rr)
	}

	if final {
		if resp.Rcode == dns.RcodeRefused && !s.nomini {
			_ = s.dbg() && s.log("got REFUSED, retry without QNAME minimization\n")
			s2 := s
			s2.depth++
			s2.qlabel = 0
			s2.nomini = true
			return r.recurseFromRoot(s2)
		}
		if len(answer) > 0 {
			_ = s.dbg() && s.log("ANSWER for %s %q: %v\n", DnsTypeToString(qtype), qname, answer)
			return resp, s.nsaddr, nil
		}
		if len(cnames) == 0 {
			var err error
			if resp.Rcode == dns.RcodeSuccess && !resp.MsgHdr.Authoritative && s.qtype == dns.TypeNS && qtype == dns.TypeNS {
				// use the previous NS response, if any
				err = errEmptyNS
			}
			if s.dbg() {
				suffix := ""
				if resp.MsgHdr.Authoritative {
					suffix = " AUTH"
				}
				if err != nil {
					suffix += " " + err.Error()
				}
				s.log("EMPTY %s for %s %q%s\n", dns.RcodeToString[resp.Rcode], DnsTypeToString(qtype), qname, suffix)
			}
		}
	}

	if len(answer) == 0 && len(cnames) > 0 {
		var cnameError error
		_ = s.dbg() && s.log("CNAMEs for %q: %v\n", qname, cnames)
		for _, cname := range cnames {
			s2 := s
			s2.depth++
			s2.qname = cname
			s2.qlabel = 0
			if cmsg, srv, err := r.recurseFromRoot(s2); err == nil {
				if resp.Zero { // don't modify cached responses
					resp = &dns.Msg{
						MsgHdr: resp.MsgHdr,
						Question: []dns.Question{{
							Name:   s.qname,
							Qtype:  s.qtype,
							Qclass: dns.ClassINET,
						}},
						Answer: append([]dns.RR{}, resp.Answer...),
					}
				}
				resp.Answer = append(resp.Answer, cmsg.Answer...)
				resp.Ns = nil
				resp.Extra = nil
				return resp, srv, nil
			} else {
				_ = s.dbg() && s.log("error resolving CNAME %q: %v\n", qname, err)
				cnameError = err
			}
		}
		return nil, s.nsaddr, cnameError
	}

	var authError error
	var authorities []dns.RR
	authoritiesMsgHdr := resp.MsgHdr

	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			authorities = append(authorities, ns)
		}
	}

	if !final {
		for _, rr := range resp.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				authorities = append(authorities, ns)
			}
		}

		if len(authorities) == 0 {
			if final {
				_ = s.dbg() && s.log("no more authorities available\n")
				return resp, s.nsaddr, nil
			}
			_ = s.dbg() && s.log("no authoritative NS found for %q, using previous\n", qname)
			s.depth++
			s.qlabel++
			return r.recurse(s)
		}

		gluemap := make(map[string][]netip.Addr)
		var extraans []dns.RR
		for _, rr := range resp.Extra {
			if addr := AddrFromRR(rr); addr.IsValid() {
				gluename := dns.CanonicalName(rr.Header().Name)
				if gluename == s.qname {
					if (s.qtype == dns.TypeA && addr.Is4()) || (s.qtype == dns.TypeAAAA && addr.Is6()) {
						extraans = append(extraans, rr)
					}
				}
				if r.useable(addr) {
					gluemap[gluename] = append(gluemap[gluename], addr)
				}
			}
		}

		if len(extraans) > 0 {
			_ = s.dbg() && s.log("EXTRA ANSWER for %s %q: %v\n", DnsTypeToString(s.qtype), s.qname, extraans)
			resp = &dns.Msg{
				MsgHdr: resp.MsgHdr,
				Question: []dns.Question{{
					Name:   s.qname,
					Qtype:  s.qtype,
					Qclass: dns.ClassINET,
				}},
				Answer: extraans,
			}
			return resp, s.nsaddr, nil
		}

		var authWithoutGlue []string
		var authOrder []string

		for _, nsrr := range authorities {
			if nsrr, ok := nsrr.(*dns.NS); ok {
				gluename := dns.CanonicalName(nsrr.Ns)
				if len(gluemap[gluename]) > 0 {
					authOrder = append(authOrder, gluename)
				} else {
					authWithoutGlue = append(authWithoutGlue, gluename)
				}
			}
		}
		authOrder = append(authOrder, authWithoutGlue...)

		for _, authority := range authOrder {
			authAddrs := gluemap[authority]

			if len(authAddrs) == 0 {
				_ = s.dbg() && s.log("authority %v has no glue\n", authority)
				for _, authQtype := range r.authQtypes() {
					var authAddrsResp *dns.Msg
					if resp.MsgHdr.Authoritative {
						if (final || idx == 0) && authQtype == s.qtype {
							_ = s.dbg() && s.log("asking directly for final %s %q\n", DnsTypeToString(s.qtype), s.qname)
							s2 := s
							s2.depth++
							s2.qlabel = 64
							if m, _, e := r.recurse(s2); e == nil && m != nil && m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
								return m, s2.nsaddr, e
							}
						}

						_ = s.dbg() && s.log("asking directly for %s %q\n", DnsTypeToString(authQtype), authority)
						s2 := s
						s2.depth++
						s2.qname = authority
						s2.qtype = authQtype
						s2.qlabel = 64
						if m, _, e := r.recurse(s2); e == nil && m != nil && m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
							authAddrsResp = m
						}
					}
					if authAddrsResp == nil {
						s2 := s
						s2.depth++
						s2.qname = authority
						s2.qtype = authQtype
						s2.qlabel = 0
						authAddrsResp, _, _ = r.recurseFromRoot(s2)
					}
					if authAddrsResp != nil {
						if len(authAddrsResp.Answer) > 0 {
							_ = s.dbg() && s.log("resolved authority %s %q to %v\n", DnsTypeToString(authQtype), authority, authAddrsResp.Answer)
							for _, r := range authAddrsResp.Answer {
								authAddrs = append(authAddrs, AddrFromRR(r))
							}
							break
						} else if authAddrsResp.Authoritative {
							_ = s.dbg() && s.log("EMPTY authority %s %q\n", DnsTypeToString(authQtype), authority)
						}
					}
				}
			}

			_ = s.dbg() && s.log("authority %v %v\n", authority, authAddrs)
			for _, authaddr := range authAddrs {
				s2 := s
				s2.nsaddr = authaddr
				s2.depth++
				s2.qlabel++
				answers, srv, err := r.recurse(s2)
				if err == nil {
					if answerTerminates(answers) {
						return answers, srv, err
					}
				} else {
					if s.errorTerminates(err) {
						return answers, srv, err
					}
					_ = s.dbg() && s.log("authority error: %s: %v\n", authority, err)
					authError = err
				}
			}
		}
	}

	if final || idx == 0 {
		if qtype == dns.TypeNS && s.qtype == dns.TypeNS {
			_ = s.dbg() && s.log("ANSWER with referral NS\n")
			resp = &dns.Msg{
				MsgHdr: authoritiesMsgHdr,
				Question: []dns.Question{{
					Name:   s.qname,
					Qtype:  s.qtype,
					Qclass: dns.ClassINET,
				}},
				Answer: authorities,
			}
			return resp, s.nsaddr, nil
		}
	}
	err = ErrNoResponse
	if authError != nil {
		err = failError{authError}
	}
	return nil, s.nsaddr, err
}

var ErrInvalidCookie = errors.New("invalid cookie")

func (r *Recursive) setNetError(protocol string, nsaddr netip.Addr, err error) (isIpv6err, isUdpErr bool) {
	if err != nil {
		isIpv6err = nsaddr.Is6()
		_, ok := err.(net.Error)
		ok = ok || errors.Is(err, io.EOF)
		if ok {
			var m map[netip.Addr]netError
			switch protocol {
			case "udp":
				isUdpErr = true
				m = r.udperrs
			case "tcp":
				m = r.tcperrs
			}
			if m != nil {
				r.mu.Lock()
				m[nsaddr] = netError{Err: err, When: time.Now()}
				r.mu.Unlock()
			}
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

func (r *Recursive) sendQueryUsing(s state, protocol string) (msg *dns.Msg, err error) {
	if s.cache != nil {
		if _, msg = s.cache.DnsGet(s.nsaddr, s.qname, s.qtype); msg != nil {
			if s.dbg() {
				s.log("cached answer: @%s %s %q => %s [%d+%d+%d A/N/E]\n",
					s.nsaddr, DnsTypeToString(s.qtype), s.qname,
					dns.RcodeToString[msg.Rcode],
					len(msg.Answer), len(msg.Ns), len(msg.Extra))
			}
			return
		}
	}

	if s.ctx.Err() != nil {
		return nil, s.ctx.Err()
	}

	if !r.useable(s.nsaddr) {
		return nil, net.ErrClosed
	}

	/*if err = r.getNetError(protocol, s.nsaddr); err != nil {
		_ = s.dbg() && s.log("cached error: @%s %s %q => %v\n", s.nsaddr, DnsTypeToString(s.qtype), s.qname, err)
		return
	}*/

	var network string
	if s.nsaddr.Is4() {
		network = protocol + "4"
	} else {
		network = protocol + "6"
	}

	if r.rateLimiter != nil {
		<-r.rateLimiter
	}

	if s.dbg() {
		var protostr string
		var dash6str string
		if protocol != "udp" {
			protostr = " +" + protocol
		}
		if s.nsaddr.Is6() {
			dash6str = " -6"
		}
		s.log("SENDING %s: @%s%s%s %s %q", network, s.nsaddr, protostr, dash6str, DnsTypeToString(s.qtype), s.qname)
	}

	var nconn net.Conn
	var rtt time.Duration

	if nconn, err = r.DialContext(s.ctx, network, netip.AddrPortFrom(s.nsaddr, 53).String()); err == nil {
		dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
		defer dnsconn.Close()

		m := new(dns.Msg)
		m.SetQuestion(s.qname, s.qtype)

		var clicookie string

		r.mu.RLock()
		cookiernd := r.cookiernd
		srvcookie, hasSrvCookie := r.srvcookies[s.nsaddr]
		r.mu.RUnlock()

		useCookies := !hasSrvCookie || srvcookie != ""

		if useCookies {
			var h maphash.Hash
			cookiebuf := make([]byte, 8)
			binary.NativeEndian.PutUint64(cookiebuf, cookiernd)
			h.Write(cookiebuf)
			h.Write(s.nsaddr.AsSlice())
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

		c := dns.Client{UDPSize: dns.DefaultMsgSize}
		msg, rtt, err = c.ExchangeWithConnContext(s.ctx, m, dnsconn)
		if msg != nil && useCookies {
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
				r.mu.Lock()
				r.srvcookies[s.nsaddr] = newsrvcookie
				r.mu.Unlock()
			}
		}
	}

	isIpv6Err, isUdpErr := r.setNetError(protocol, s.nsaddr, err)
	ipv6disabled := isIpv6Err && r.maybeDisableIPv6(err)
	udpDisabled := isUdpErr && r.maybeDisableUdp(err)

	if s.logw != nil {
		if msg != nil {
			fmt.Fprintf(s.logw, " => %s [%d+%d+%d A/N/E] (%v, %d bytes",
				dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra),
				rtt.Round(time.Millisecond), msg.Len())
			if msg.MsgHdr.Truncated {
				fmt.Fprintf(s.logw, " TRNC")
			}
			if msg.MsgHdr.Authoritative {
				fmt.Fprintf(s.logw, " AUTH")
			}
			if opt := msg.IsEdns0(); opt != nil {
				if er := opt.ExtendedRcode(); er != 0 {
					fmt.Fprintf(s.logw, " EDNS=%s", dns.ExtendedErrorCodeToString[uint16(er)])
				}
			}
			fmt.Fprintf(s.logw, ")")
		}
		if err != nil {
			fmt.Fprintf(s.logw, " error: %v", err)
		}
		if ipv6disabled {
			fmt.Fprintf(s.logw, " (IPv6 disabled)")
		}
		if udpDisabled {
			fmt.Fprintf(s.logw, " (UDP disabled)")
		}
		fmt.Fprintln(s.logw)
	}

	return
}

func (r *Recursive) sendQuery(s state) (msg *dns.Msg, err error) {
	if r.usingUDP() {
		msg, err = r.sendQueryUsing(s, "udp")
		if msg != nil {
			if msg.MsgHdr.Truncated {
				msg = nil
				_ = s.dbg() && s.log("message truncated; retry using TCP\n")
			} else if msg.MsgHdr.Rcode == dns.RcodeFormatError {
				msg = nil
				_ = s.dbg() && s.log("got FORMERR, retry using TCP without cookies\n")
			}
		}
	}
	if (msg == nil || err != nil) && r.useable(s.nsaddr) {
		msg, err = r.sendQueryUsing(s, "tcp")
	}
	if err == nil && s.cache != nil {
		s.cache.DnsSet(s.nsaddr, msg)
	}
	return
}

func (r *Recursive) maybeDisableIPv6(err error) (disabled bool) {
	if ne, ok := err.(net.Error); ok {
		if !ne.Timeout() && strings.Contains(ne.Error(), "network is unreachable") {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.useIPv6 {
				disabled = true
				r.useIPv6 = false
				var idx int
				for i := range r.rootServers {
					if r.rootServers[i].Is4() {
						r.rootServers[idx] = r.rootServers[i]
						idx++
					}
				}
				r.rootServers = r.rootServers[:idx]
			}
		}
	}
	return
}

func (r *Recursive) maybeDisableUdp(err error) (disabled bool) {
	if ne, ok := err.(net.Error); ok {
		if !ne.Timeout() && strings.Contains(ne.Error(), "network not implemented") {
			r.mu.Lock()
			defer r.mu.Unlock()
			disabled = r.useUDP
			r.useUDP = false
		}
	}
	return
}
