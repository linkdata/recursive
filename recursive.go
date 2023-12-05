package recursive

import (
	"context"
	"errors"
	"fmt"
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
	mu          sync.RWMutex
	useIPv4     bool
	useIPv6     bool
	rootServers []netip.Addr
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

func logf(logw io.Writer, depth int, format string, args ...any) bool {
	fmt.Fprintf(logw, "[%2d] %*s", depth, depth, "")
	fmt.Fprintf(logw, format, args...)
	return false
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
	msg, srv, err := r.recurseFromRoot(ctx, dialer, cache, logw, 0, qname, qtype)
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

func (r *Recursive) recurseFromRoot(ctx context.Context, dialer proxy.ContextDialer, cache Cacher, logw io.Writer, depth int, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	_ = (logw != nil) && logf(logw, depth, "resolving from root %s %q\n", DnsTypeToString(qtype), qname)

	for i := 0; i < maxRootAttempts; i++ {
		if server := r.nextRoot(i); server.IsValid() {
			msg, srv, err = r.recurse(ctx, dialer, cache, logw, depth, server, qname, qtype, 1)
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

func (r *Recursive) recurse(ctx context.Context, dialer proxy.ContextDialer, cache Cacher, logw io.Writer, depth int, nsaddr netip.Addr, orgqname string, orgqtype uint16, qlabel int) (*dns.Msg, netip.Addr, error) {
	if depth >= maxDepth {
		_ = (logw != nil) && logf(logw, depth, "maximum depth reached\n")
		return nil, netip.Addr{}, ErrMaxDepth
	}

	qname := orgqname
	qtype := orgqtype

	idx, final := dns.PrevLabel(qname, qlabel)
	if !final {
		qtype = dns.TypeNS
		qname = qname[idx:]
	}

	resp, err := r.sendQuery(ctx, dialer, cache, logw, depth, nsaddr, qname, qtype)
	if err != nil {
		return nil, nsaddr, err
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
			_ = (logw != nil) && logf(logw, depth, "ANSWER for %s %q: %v\n", DnsTypeToString(qtype), qname, answer)
			return resp, nsaddr, nil
		}
		if resp.Rcode == dns.RcodeNameError {
			_ = (logw != nil) && logf(logw, depth, "NXDOMAIN for %s %q\n", DnsTypeToString(qtype), qname)
			return resp, nsaddr, nil
		}
		if len(cnames) == 0 && resp.MsgHdr.Authoritative {
			_ = (logw != nil) && logf(logw, depth, "authoritative response with no ANSWERs\n")
			return resp, nsaddr, nil
		}
	}

	if len(answer) == 0 && len(cnames) > 0 {
		var cnameError error
		_ = (logw != nil) && logf(logw, depth, "CNAMEs for %q: %v\n", qname, cnames)
		for _, cname := range cnames {
			if cmsg, srv, err := r.recurseFromRoot(ctx, dialer, cache, logw, depth+1, cname, orgqtype); err == nil {
				resp.Answer = append(resp.Answer, cmsg.Answer...)
				resp.Ns = nil
				resp.Extra = nil
				return resp, srv, nil
			} else {
				_ = (logw != nil) && logf(logw, depth, "error resolving CNAME %q: %v\n", qname, err)
				cnameError = err
			}
		}
		return nil, nsaddr, cnameError
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
			_ = (logw != nil) && logf(logw, depth, "no more authorities available\n")
			return resp, nsaddr, nil
		}
		_ = (logw != nil) && logf(logw, depth, "no authoritative NS found for %q, using previous\n", qname)
		return r.recurse(ctx, dialer, cache, logw, depth+1, nsaddr, orgqname, orgqtype, qlabel+1)
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

	_ = (logw != nil) && logf(logw, depth, "authorities with glue records: %v\n", authWithGlue)
	for _, authority := range authWithGlue {
		for _, authaddr := range gluemap[authority] {
			answers, srv, err := r.recurse(ctx, dialer, cache, logw, depth+1, authaddr, orgqname, orgqtype, qlabel+1)
			switch err {
			case nil, ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
				return answers, srv, err
			}
			authError = err
		}
	}

	_ = (logw != nil) && logf(logw, depth, "authorities without glue records: %v\n", authWithoutGlue)
	for _, authority := range authWithoutGlue {
		for _, authQtype := range r.authQtypes() {
			authAddrs, srv, err := r.recurseFromRoot(ctx, dialer, cache, logw, depth+1, authority, authQtype)
			switch err {
			case ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
				return nil, srv, err
			}
			if authAddrs != nil && len(authAddrs.Answer) > 0 {
				_ = (logw != nil) && logf(logw, depth, "resolved authority %s %q to %v\n", DnsTypeToString(authQtype), authority, authAddrs.Answer)
				for _, nsrr := range authAddrs.Answer {
					if authaddr := AddrFromRR(nsrr); authaddr.IsValid() {
						if r.useable(authaddr) {
							answers, srv, err := r.recurse(ctx, dialer, cache, logw, depth+1, authaddr, orgqname, orgqtype, qlabel+1)
							switch err {
							case nil, ErrNoResponse, dns.ErrRdata, ErrMaxDepth:
								return answers, srv, err
							}
							authError = err
						}
					}
				}
			} else if err != nil {
				authError = err
				_ = (logw != nil) && logf(logw, depth, "error querying authority %q: %v\n", authority, err)
			}
		}
	}
	if (final || idx == 0) && orgqtype == dns.TypeNS && qtype == dns.TypeNS {
		_ = (logw != nil) && logf(logw, depth, "ANSWER with referral NS\n")
		resp = &dns.Msg{
			MsgHdr: authoritiesMsgHdr,
			Question: []dns.Question{{
				Name:   orgqname,
				Qtype:  orgqtype,
				Qclass: dns.ClassINET,
			}},
			Answer: authorities,
		}
		return resp, nsaddr, nil
	}
	if authError != nil {
		return nil, nsaddr, authError
	}
	return nil, nsaddr, ErrNoResponse
}

func (r *Recursive) sendQueryUsing(ctx context.Context, dialer proxy.ContextDialer, cache Cacher, logw io.Writer, depth int, protocol string, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	if _, msg = cache.DnsGet(nsaddr, qname, qtype); msg != nil {
		if logw != nil {
			logf(logw, depth, "cache hit: @%s %s %q => %s [%d+%d+%d A/N/E]\n",
				nsaddr, DnsTypeToString(qtype), qname, dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra))
		}
		return
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if !r.useable(nsaddr) {
		return nil, net.ErrClosed
	}

	var network string
	if nsaddr.Is4() {
		network = protocol + "4"
	} else {
		network = protocol + "6"
	}

	if logw != nil {
		var protostr string
		var dash6str string
		if protocol != "udp" {
			protostr = " +" + protocol
		}
		if nsaddr.Is6() {
			dash6str = " -6"
		}
		logf(logw, depth, "sending %s: @%s%s%s %s %q", network, nsaddr, protostr, dash6str, DnsTypeToString(qtype), qname)
	}

	var nconn net.Conn
	var rtt time.Duration
	if nconn, err = dialer.DialContext(ctx, network, netip.AddrPortFrom(nsaddr, 53).String()); err == nil {
		dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
		defer dnsconn.Close()
		m := new(dns.Msg)
		m.SetQuestion(qname, qtype).SetEdns0(dns.DefaultMsgSize, false).RecursionDesired = false
		c := dns.Client{UDPSize: dns.DefaultMsgSize}
		msg, rtt, err = c.ExchangeWithConnContext(ctx, m, dnsconn)
	}

	ipv6disabled := (err != nil && nsaddr.Is6() && r.maybeDisableIPv6(depth, err))

	if logw != nil {
		if msg != nil {
			fmt.Fprintf(logw, " => %s [%d+%d+%d A/N/E] (%v, %d bytes", dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra), rtt.Round(time.Millisecond), msg.Len())
			if msg.MsgHdr.Truncated {
				fmt.Fprintf(logw, " TRNC")
			}
			if msg.MsgHdr.Authoritative {
				fmt.Fprintf(logw, " AUTH")
			}
			fmt.Fprintf(logw, ")")
		}
		if err != nil {
			fmt.Fprintf(logw, " error: %v", err)
		}
		if ipv6disabled {
			fmt.Fprintf(logw, " (IPv6 disabled)")
		}
		fmt.Fprintln(logw)
	}

	return
}

func (r *Recursive) sendQuery(ctx context.Context, dialer proxy.ContextDialer, cache Cacher, logw io.Writer, depth int, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	msg, err = r.sendQueryUsing(ctx, dialer, cache, logw, depth, "udp", nsaddr, qname, qtype)
	if msg != nil && msg.MsgHdr.Truncated {
		_ = (logw != nil) && logf(logw, depth, "message truncated; retry using TCP\n")
		msg = nil
	}
	if (msg == nil || err != nil) && r.useable(nsaddr) {
		msg, err = r.sendQueryUsing(ctx, dialer, cache, logw, depth, "tcp", nsaddr, qname, qtype)
	}
	if err == nil {
		cache.DnsSet(nsaddr, msg)
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
