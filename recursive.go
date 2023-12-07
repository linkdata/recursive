package recursive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	mathrand "math/rand"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

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
	DefaultCache  = NewCache()
)

var defaultNetDialer net.Dialer
var _ Resolver = (*Recursive)(nil)

type Recursive struct {
	cookiernd   []byte
	mu          sync.RWMutex
	useIPv4     bool
	useIPv6     bool
	rootServers []netip.Addr
	srvcookies  map[netip.Addr]string
}

func NewWithOptions(roots4, roots6 []netip.Addr) *Recursive {
	var root4, root6 []netip.Addr
	if roots4 != nil {
		root4 = append(root4, roots4...)
		mathrand.Shuffle(len(root4), func(i, j int) { root4[i], root4[j] = root4[j], root4[i] })
	}
	if roots6 != nil {
		root6 = append(root6, roots6...)
		mathrand.Shuffle(len(root6), func(i, j int) { root6[i], root6[j] = root6[j], root6[i] })
	}

	roots := make([]netip.Addr, 0, len(root4)+len(root6))
	n := min(len(root4), len(root6))
	for i := 0; i < n; i++ {
		roots = append(roots, root4[i], root6[i])
	}
	roots = append(roots, root4[n:]...)
	roots = append(roots, root6[n:]...)
	cookiernd := make([]byte, 8)
	rand.Read(cookiernd)
	return &Recursive{
		cookiernd:   cookiernd,
		useIPv4:     root4 != nil,
		useIPv6:     root6 != nil,
		rootServers: roots,
		srvcookies:  make(map[netip.Addr]string),
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

// ResolveWithOptions will perform a recursive DNS resolution for the provided name and record type,
// using the given dialer, and if logw is non-nil, write a log of events.
func (r *Recursive) ResolveWithOptions(ctx context.Context, dialer proxy.ContextDialer, cache Cacher, logw io.Writer, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	if dialer == nil {
		dialer = &defaultNetDialer
	}
	var start time.Time
	if logw != nil {
		start = time.Now()
	}
	qname = dns.CanonicalName(qname)
	if _, ok := dns.IsDomainName(qname); !ok {
		return nil, netip.Addr{}, dns.ErrRdata
	}
	s := state{
		ctx:    ctx,
		dialer: dialer,
		cache:  cache,
		logw:   logw,
		depth:  0,
		nsaddr: netip.Addr{},
		qname:  qname,
		qtype:  qtype,
		qlabel: 0,
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

type state struct {
	ctx    context.Context
	dialer proxy.ContextDialer
	cache  Cacher
	logw   io.Writer
	depth  int
	nsaddr netip.Addr
	qname  string
	qtype  uint16
	qlabel int
	noglue map[string]struct{}
}

func (s *state) dbg() bool {
	return s.logw != nil
}

func (s *state) log(format string, args ...any) bool {
	fmt.Fprintf(s.logw, "[%2d] %*s", s.depth, s.depth, "")
	fmt.Fprintf(s.logw, format, args...)
	return false
}

func (r *Recursive) recurseFromRoot(s state) (msg *dns.Msg, srv netip.Addr, err error) {
	_ = s.dbg() && s.log("resolving from root %s %q\n", DnsTypeToString(s.qtype), s.qname)

	for i := 0; i < maxRootAttempts; i++ {
		if server := r.nextRoot(i); server.IsValid() {
			s.nsaddr = server
			s.qlabel = 1
			msg, srv, err = r.recurse(s)
			switch err {
			case nil, ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
				return
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
		if resp.Rcode == dns.RcodeNameError {
			_ = s.dbg() && s.log("NXDOMAIN for %s %q\n", DnsTypeToString(qtype), qname)
			return resp, s.nsaddr, nil
		}
		if len(cnames) == 0 && resp.MsgHdr.Authoritative {
			_ = s.dbg() && s.log("authoritative response with no ANSWERs\n")
			return resp, s.nsaddr, nil
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
	for _, rr := range resp.Extra {
		if addr := AddrFromRR(rr); addr.IsValid() {
			if r.useable(addr) {
				gluename := dns.CanonicalName(rr.Header().Name)
				gluemap[gluename] = append(gluemap[gluename], addr)
			}
		}
	}

	var authWithGlue, authWithoutGlue []string
	var authError error

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
			case nil, ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
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
				// try asking it directly for the IP
				s2 := s
				s2.depth++
				s2.qname = authority
				s2.qtype = authQtype
				s2.qlabel = 64
				authAddrs, srv, err = r.recurse(s2)
				switch err {
				case ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
					return nil, srv, err
				}
			}
			if authAddrs == nil {
				s2 := s
				s2.depth++
				s2.qname = authority
				s2.qtype = authQtype
				authAddrs, srv, err = r.recurseFromRoot(s2)
				switch err {
				case ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
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
							case nil, ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
								return answers, srv, err
							}
							authError = err
						}
					}
				}
			} else if err != nil {
				if s.noglue == nil {
					s.noglue = make(map[string]struct{})
				}
				s.noglue[authority] = struct{}{}
				authError = err
				_ = s.dbg() && s.log("error querying authority %q: %v\n", authority, err)
			}
		}
	}
	if (final || idx == 0) && s.qtype == dns.TypeNS && qtype == dns.TypeNS {
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
	if authError != nil {
		return nil, s.nsaddr, authError
	}
	return nil, s.nsaddr, ErrNoResponse
}

var ErrInvalidCookie = errors.New("invalid cookie")

func (r *Recursive) sendQueryUsing(s state, protocol string) (msg *dns.Msg, err error) {
	if _, msg = s.cache.DnsGet(s.nsaddr, s.qname, s.qtype); msg != nil {
		if s.dbg() {
			s.log("cache hit: @%s %s %q => %s [%d+%d+%d A/N/E]\n",
				s.nsaddr, DnsTypeToString(s.qtype), s.qname, dns.RcodeToString[msg.Rcode],
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
		s.log("sending %s: @%s%s%s %s %q", network, s.nsaddr, protostr, dash6str, DnsTypeToString(s.qtype), s.qname)
	}

	var nconn net.Conn
	var rtt time.Duration
	if nconn, err = s.dialer.DialContext(s.ctx, network, netip.AddrPortFrom(s.nsaddr, 53).String()); err == nil {
		dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
		defer dnsconn.Close()
		m := new(dns.Msg)
		m.SetQuestion(s.qname, s.qtype)
		m.RecursionDesired = false
		e := new(dns.OPT)
		e.Hdr.Name = "."
		e.Hdr.Rrtype = dns.TypeOPT
		e.SetUDPSize(dns.DefaultMsgSize)
		var h maphash.Hash
		h.Write(r.cookiernd)
		h.Write(s.nsaddr.AsSlice())
		if la := nconn.LocalAddr(); la != nil {
			h.Write([]byte(la.String()))
		}
		clicookie := hex.EncodeToString(h.Sum(nil))
		r.mu.RLock()
		srvcookie := r.srvcookies[s.nsaddr]
		r.mu.RUnlock()
		e.Option = append(e.Option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: clicookie + srvcookie,
		})
		m.Extra = append(m.Extra, e)
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

	ipv6disabled := (err != nil && s.nsaddr.Is6() && r.maybeDisableIPv6(s.depth, err))

	if s.logw != nil {
		if msg != nil {
			fmt.Fprintf(s.logw, " => %s [%d+%d+%d A/N/E] (%v, %d bytes", dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra), rtt.Round(time.Millisecond), msg.Len())
			if msg.MsgHdr.Truncated {
				fmt.Fprintf(s.logw, " TRNC")
			}
			if msg.MsgHdr.Authoritative {
				fmt.Fprintf(s.logw, " AUTH")
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
