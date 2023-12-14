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
*/

//go:generate go run ./cmd/genhints roothints.gen.go

const (
	maxDepth        = 30 // maximum recursion depth
	maxRootAttempts = 2  // maximum number of root servers to try
)

var (
	// ErrMaxDepth is returned when recursive resolving exceeds the allowed limit.
	ErrMaxDepth = fmt.Errorf("recursion depth exceeded %d", maxDepth)
	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	// Consider it equivalent to SERVFAIL.
	ErrNoResponse = errors.New("no authoritative response")
	errEmptyNS    = errors.New("ignoring non-auth empty NS")
	DefaultCache  = NewCache()
)

var defaultNetDialer net.Dialer
var _ Resolver = (*Recursive)(nil)

type netError struct {
	Err  error
	When time.Time
}

type Recursive struct {
	mu          sync.RWMutex
	useIPv4     bool
	useIPv6     bool
	rootServers []netip.Addr
	cookiernd   uint64
	srvcookies  map[netip.Addr]string
	udperrs     map[netip.Addr]netError
	tcperrs     map[netip.Addr]netError
}

func NewWithOptions(roots4, roots6 []netip.Addr) *Recursive {
	var root4, root6 []netip.Addr
	if roots4 != nil {
		root4 = append(root4, roots4...)
		rand.Shuffle(len(root4), func(i, j int) { root4[i], root4[j] = root4[j], root4[i] })
	}
	if roots6 != nil {
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
		useIPv4:     root4 != nil,
		useIPv6:     root6 != nil,
		rootServers: roots,
		cookiernd:   rand.Uint64(),
		srvcookies:  make(map[netip.Addr]string),
		udperrs:     make(map[netip.Addr]netError),
		tcperrs:     make(map[netip.Addr]netError),
	}
}

func New() *Recursive {
	return NewWithOptions(Roots4, Roots6)
}

type rootRtt struct {
	addr netip.Addr
	rtt  time.Duration
}

func timeRoot(ctx context.Context, dialer proxy.ContextDialer, wg *sync.WaitGroup, rt *rootRtt) {
	defer wg.Done()
	const numProbes = 3
	network := "tcp4"
	if rt.addr.Is6() {
		network = "tcp6"
	}
	rt.rtt = time.Hour
	var rtt time.Duration
	for i := 0; i < numProbes; i++ {
		now := time.Now()
		conn, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(rt.addr, 53).String())
		if err != nil {
			return
		}
		rtt += time.Since(now)
		conn.Close()
	}
	rt.rtt = rtt / numProbes
}

// ResetCookies generates a new DNS client cookie and clears the known DNS server cookies.
func (r *Recursive) ResetCookies() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cookiernd = rand.Uint64()
	clear(r.srvcookies)
}

// OrderRoots sorts the root server list by their current latency and removes those that don't respond.
func (r *Recursive) OrderRoots(ctx context.Context, dialer proxy.ContextDialer) {
	if dialer == nil {
		dialer = &defaultNetDialer
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	var l []*rootRtt
	var wg sync.WaitGroup
	for _, addr := range r.rootServers {
		rt := &rootRtt{addr: addr}
		l = append(l, rt)
		wg.Add(1)
		go timeRoot(ctx, dialer, &wg, rt)
	}
	wg.Wait()
	sort.Slice(l, func(i, j int) bool { return l[i].rtt < l[j].rtt })
	r.rootServers = r.rootServers[:0]
	r.useIPv4 = false
	r.useIPv6 = false
	for _, rt := range l {
		if rt.rtt < time.Minute {
			r.useIPv4 = r.useIPv4 || rt.addr.Is4()
			r.useIPv6 = r.useIPv6 || rt.addr.Is6()
			r.rootServers = append(r.rootServers, rt.addr)
		}
	}
}

type rootQuery struct {
	nsaddr netip.Addr
	qname  string
	qtype  uint16
}

type state struct {
	ctx    context.Context
	start  time.Time
	dialer proxy.ContextDialer
	cache  Cacher
	logw   io.Writer
	depth  int
	nsaddr netip.Addr
	qname  string
	qtype  uint16
	qlabel int
	stack  map[rootQuery]struct{}
}

// ResolveWithOptions will perform a recursive DNS resolution for the provided name and record type,
// using the given dialer, and if logw is non-nil, write a log of events.
func (r *Recursive) ResolveWithOptions(ctx context.Context, dialer proxy.ContextDialer, cache Cacher, logw io.Writer, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	if dialer == nil {
		dialer = &defaultNetDialer
	}
	start := time.Now()
	qname = dns.CanonicalName(qname)
	if _, ok := dns.IsDomainName(qname); !ok {
		return nil, netip.Addr{}, dns.ErrRdata
	}
	s := state{
		ctx:    ctx,
		start:  start,
		dialer: dialer,
		cache:  cache,
		logw:   logw,
		depth:  0,
		nsaddr: netip.Addr{},
		qname:  qname,
		qtype:  qtype,
		qlabel: 0,
		stack:  make(map[rootQuery]struct{}),
	}
	msg, srv, err := r.recurseFromRoot(s)
	if logw != nil {
		fmt.Fprintf(logw, "\n%v\n;; Query time: %v\n;; SERVER: %v\n", msg, time.Since(start).Round(time.Millisecond), srv)
	}
	return msg, srv, err
}

// Resolve will perform a recursive DNS resolution for the provided name and record type.
func (r *Recursive) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return r.ResolveWithOptions(ctx, nil, DefaultCache, nil, qname, qtype)
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
	_ = s.dbg() && s.log("resolving from root %s %q\n", DnsTypeToString(s.qtype), s.qname)
	for i := 0; i < maxRootAttempts; i++ {
		if server := r.nextRoot(i); server.IsValid() {
			rq := rootQuery{server, s.qname, s.qtype}
			if _, ok := s.stack[rq]; !ok {
				s.stack[rq] = struct{}{}
				s.nsaddr = server
				s.qlabel = 1
				msg, srv, err = r.recurse(s)
				delete(s.stack, rq)
				switch err {
				case nil, ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
					return
				}
			}
		}
	}
	return
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

func (r *Recursive) recurse(s state) (*dns.Msg, netip.Addr, error) {
	if s.depth >= maxDepth {
		_ = s.dbg() && s.log("maximum depth reached\n")
		return nil, netip.Addr{}, ErrMaxDepth
	}

	qname := s.qname
	qtype := s.qtype

	idx, final := dns.PrevLabel(qname, s.qlabel)
	if !final {
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
		if len(answer) > 0 {
			_ = s.dbg() && s.log("ANSWER for %s %q: %v\n", DnsTypeToString(qtype), qname, answer)
			return resp, s.nsaddr, nil
		}
		if len(cnames) == 0 {
			var err error
			if resp.Rcode == dns.RcodeSuccess && !resp.MsgHdr.Authoritative && s.qtype == dns.TypeNS && qtype == dns.TypeNS {
				// use the previous NS response, if any (test with NS google.tw.cn)
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
			return resp, s.nsaddr, err
		}
	}

	if len(answer) == 0 && len(cnames) > 0 {
		var cnameError error
		_ = s.dbg() && s.log("CNAMEs for %q: %v\n", qname, cnames)
		for _, cname := range cnames {
			s2 := s
			s2.depth++
			s2.qname = cname
			if cmsg, srv, err := r.recurseFromRoot(s2); err == nil {
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

		var authWithGlue, authWithoutGlue []string

		for _, nsrr := range authorities {
			if nsrr, ok := nsrr.(*dns.NS); ok {
				gluename := dns.CanonicalName(nsrr.Ns)
				if len(gluemap[gluename]) > 0 {
					authWithGlue = append(authWithGlue, gluename)
				} else {
					authWithoutGlue = append(authWithoutGlue, gluename)
				}
			}
		}

		_ = s.dbg() && s.log("authorities with glue records: %v\n", authWithGlue)
		for _, authority := range authWithGlue {
			for _, authaddr := range gluemap[authority] {
				s2 := s
				s2.nsaddr = authaddr
				s2.depth++
				s2.qlabel++
				answers, srv, err := r.recurse(s2)
				switch err {
				case nil:
					if answers.Authoritative || answers.Rcode != dns.RcodeServerFailure {
						return answers, srv, err
					}
				case ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
					return answers, srv, err
				}
				authError = err
			}
		}

		_ = s.dbg() && s.log("authorities without glue records: %v\n", authWithoutGlue)
		for _, authority := range authWithoutGlue {
			for _, authQtype := range r.authQtypes() {
				var authAddrs *dns.Msg
				var srv netip.Addr
				var err error
				if resp.MsgHdr.Authoritative {
					_ = s.dbg() && s.log("asking directly for %s %q\n", DnsTypeToString(authQtype), authority)
					s2 := s
					s2.depth++
					s2.qname = authority
					s2.qtype = authQtype
					s2.qlabel = 64
					if m, _, e := r.recurse(s2); e == nil && m != nil && m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
						authAddrs = m
					}
				}
				if authAddrs == nil {
					s2 := s
					s2.depth++
					s2.qname = authority
					s2.qtype = authQtype
					authAddrs, srv, err = r.recurseFromRoot(s2)
					switch err {
					case dns.ErrRdata, ErrMaxDepth:
						return nil, srv, err
					}
				}
				if authAddrs != nil && len(authAddrs.Answer) > 0 {
					_ = s.dbg() && s.log("resolved authority %s %q to %v\n", DnsTypeToString(authQtype), authority, authAddrs.Answer)
					for _, nsrr := range authAddrs.Answer {
						if authaddr := AddrFromRR(nsrr); authaddr.IsValid() {
							if r.useable(authaddr) {
								s2 := s
								s2.nsaddr = authaddr
								s2.depth++
								s2.qlabel++
								answers, srv, err := r.recurse(s2)
								switch err {
								case nil:
									if answers.Authoritative || answers.Rcode != dns.RcodeServerFailure {
										return answers, srv, err
									}
								case ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
									return answers, srv, err
								}
								authError = err
							}
						}
					}
				} else if err != nil {
					authError = err
					_ = s.dbg() && s.log("error querying authority %q: %v\n", authority, err)
				}
			}
		}
	}

	if final || idx == 0 {
		if s.qtype == dns.TypeNS && qtype == dns.TypeNS {
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
	if authError != nil {
		return nil, s.nsaddr, authError
	}
	return nil, s.nsaddr, ErrNoResponse
}

var ErrInvalidCookie = errors.New("invalid cookie")

func (r *Recursive) setNetError(protocol string, nsaddr netip.Addr, err error) (isIpv6err bool) {
	if err != nil {
		isIpv6err = nsaddr.Is6()
		_, ok := err.(net.Error)
		ok = ok || errors.Is(err, io.EOF)
		if ok {
			var m map[netip.Addr]netError
			switch protocol {
			case "udp":
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

func (r *Recursive) getNetError(protocol string, nsaddr netip.Addr) error {
	var m map[netip.Addr]netError
	switch protocol {
	case "udp":
		m = r.udperrs
	case "tcp":
		m = r.tcperrs
	}
	if m != nil {
		r.mu.RLock()
		ne, ok := m[nsaddr]
		r.mu.RUnlock()
		if ok {
			if time.Since(ne.When) < time.Minute {
				return ne.Err
			}
			r.mu.Lock()
			delete(m, nsaddr)
			r.mu.Unlock()
		}
	}
	return nil
}

func (r *Recursive) sendQueryUsing(s state, protocol string) (msg *dns.Msg, err error) {
	if _, msg = s.cache.DnsGet(s.nsaddr, s.qname, s.qtype); msg != nil {
		if s.dbg() {
			s.log("cached answer: @%s %s %q => %s [%d+%d+%d A/N/E]\n",
				s.nsaddr, DnsTypeToString(s.qtype), s.qname,
				dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra))
		}
		return
	}

	if s.ctx.Err() != nil {
		return nil, s.ctx.Err()
	}

	if !r.useable(s.nsaddr) {
		return nil, net.ErrClosed
	}

	if err = r.getNetError(protocol, s.nsaddr); err != nil {
		_ = s.dbg() && s.log("cached error: @%s %s %q => %v\n", s.nsaddr, DnsTypeToString(s.qtype), s.qname, err)
		return
	}

	var network string
	if s.nsaddr.Is4() {
		network = protocol + "4"
	} else {
		network = protocol + "6"
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
	if nconn, err = s.dialer.DialContext(s.ctx, network, netip.AddrPortFrom(s.nsaddr, 53).String()); err == nil {
		dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
		defer dnsconn.Close()

		cookiernd := make([]byte, 8)
		r.mu.RLock()
		binary.NativeEndian.PutUint64(cookiernd, r.cookiernd)
		srvcookie := r.srvcookies[s.nsaddr]
		r.mu.RUnlock()

		var h maphash.Hash
		h.Write(cookiernd)
		h.Write(s.nsaddr.AsSlice())
		if la := nconn.LocalAddr(); la != nil {
			h.WriteString(la.String())
		}
		clicookie := hex.EncodeToString(h.Sum(nil))

		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(dns.DefaultMsgSize)
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: clicookie + srvcookie,
		})

		m := new(dns.Msg)
		m.SetQuestion(s.qname, s.qtype)
		m.Extra = append(m.Extra, opt)

		c := dns.Client{UDPSize: dns.DefaultMsgSize}
		msg, rtt, err = c.ExchangeWithConnContext(s.ctx, m, dnsconn)
		if msg != nil {
			if opt := msg.IsEdns0(); opt != nil {
				for _, rr := range opt.Option {
					switch rr := rr.(type) {
					case *dns.EDNS0_COOKIE:
						if strings.HasPrefix(rr.Cookie, clicookie) {
							newsrvcookie := strings.TrimPrefix(rr.Cookie, clicookie)
							if srvcookie != newsrvcookie {
								r.mu.Lock()
								r.srvcookies[s.nsaddr] = newsrvcookie
								r.mu.Unlock()
							}
						} else {
							msg = nil
							err = ErrInvalidCookie
						}
					}
				}
			}
		}
	}

	ipv6disabled := r.setNetError(protocol, s.nsaddr, err) && r.maybeDisableIPv6(s.depth, err)

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
		fmt.Fprintln(s.logw)
	}

	return
}

func (r *Recursive) sendQuery(s state) (msg *dns.Msg, err error) {
	msg, err = r.sendQueryUsing(s, "udp")
	if msg != nil && msg.MsgHdr.Truncated {
		_ = s.dbg() && s.log("message truncated; retry using TCP\n")
		msg = nil
	}
	if (msg == nil || err != nil) && r.useable(s.nsaddr) {
		msg, err = r.sendQueryUsing(s, "tcp")
	}
	if err == nil {
		s.cache.DnsSet(s.nsaddr, msg)
	}
	return
}

func (r *Recursive) maybeDisableIPv6(depth int, err error) (disabled bool) {
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
