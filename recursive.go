package recursive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

//go:generate go run ./cmd/genhints roothints.gen.go

const (
	maxDepth        = 30  // maximum recursion depth
	maxRootAttempts = 2   // maximum number of root servers to try
	maxCacheTTL     = 600 // longest allowed TTL for the cache
)

var (
	// ErrMaxDepth is returned when recursive resolving exceeds the allowed limit.
	ErrMaxDepth = fmt.Errorf("recursion depth exceeded %d", maxDepth)
	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	// Consider it equivalent to SERVFAIL.
	ErrNoResponse = errors.New("no authoritative response")
	// DefaultUdpQueryTimeout is the timeout set on UDP queries before trying TCP.
	// If set to zero, UDP will not be used.
	DefaultUdpQueryTimeout = 5 * time.Second
	// DefaultTcpQueryTimeout is the default timeout set on TCP queries.
	// If set to zero, no timeout is imposed.
	DefaultTcpQueryTimeout = 10 * time.Second
)

var defaultNetDialer net.Dialer

type Resolver struct {
	// UdpQueryTimeout is the timeout set on UDP queries before trying TCP.
	// If set to zero, UDP will not be used.
	UdpQueryTimeout time.Duration
	// TcpQueryTimeout is the timeout set on TCP queries.
	// If set to zero, no timeout is imposed.
	TcpQueryTimeout time.Duration
	queryCount      uint64 // atomic
	cacheHits       uint64 // atomic
	mu              sync.RWMutex
	useIPv4         bool
	useIPv6         bool
	rootServers     []netip.Addr
	rootIndex       int
	cache           map[cacheKey]cacheValue
}

func NewWithOptions(roots4, roots6 []netip.Addr) *Resolver {
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

	return &Resolver{
		UdpQueryTimeout: DefaultUdpQueryTimeout,
		TcpQueryTimeout: DefaultTcpQueryTimeout,
		useIPv4:         root4 != nil,
		useIPv6:         root6 != nil,
		rootServers:     roots,
		cache:           make(map[cacheKey]cacheValue),
	}
}

func New() *Resolver {
	return NewWithOptions(Roots4, Roots6)
}

func log(logw io.Writer, depth int, format string, args ...any) bool {
	fmt.Fprintf(logw, "[%2d] %*s", depth, depth, "")
	fmt.Fprintf(logw, format, args...)
	return false
}

// ResolveWithOptions will perform a recursive DNS resolution for the provided name and record type,
// using the given dialer, and if logw is non-nil, write a log of events.
func (r *Resolver) ResolveWithOptions(ctx context.Context, dialer proxy.ContextDialer, logw io.Writer, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	if dialer == nil {
		dialer = &defaultNetDialer
	}
	var start time.Time
	if logw != nil {
		start = time.Now()
	}
	msg, srv, err := r.recurseFromRoot(ctx, dialer, logw, 0, dns.CanonicalName(qname), qtype)
	if logw != nil {
		fmt.Fprintf(logw, "\n%v\n;; Query time: %v\n;; SERVER: %v\n", msg, time.Since(start).Round(time.Millisecond), srv)
	}
	return msg, srv, err
}

// Resolve will perform a recursive DNS resolution for the provided name and record type.
func (r *Resolver) Resolve(qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return r.ResolveWithOptions(context.Background(), nil, nil, qname, qtype)
}

func (r *Resolver) nextRoot(i int) (addr netip.Addr) {
	r.mu.RLock()
	if l := len(r.rootServers); l > 0 {
		addr = r.rootServers[(r.rootIndex+i)%l]
	}
	r.mu.RUnlock()
	return
}

func (r *Resolver) recurseFromRoot(ctx context.Context, dialer proxy.ContextDialer, logw io.Writer, depth int, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	var depthErrorSrv netip.Addr

	_ = (logw != nil) && log(logw, depth, "resolving from root %s %q\n", DnsTypeToString(qtype), qname)

	for i := 0; i < maxRootAttempts; i++ {
		if server := r.nextRoot(i); server.IsValid() {
			retv, srv, err := r.recurse(ctx, dialer, logw, depth, server, qname, qtype, 1)
			switch err {
			case nil, ErrNoResponse:
				return retv, srv, err
			case ErrMaxDepth:
				depthErrorSrv = srv
			}
		}
	}
	r.mu.Lock()
	r.rootIndex++
	r.mu.Unlock()
	if depthErrorSrv.IsValid() {
		return nil, depthErrorSrv, ErrMaxDepth
	}
	return nil, netip.Addr{}, ErrNoResponse
}

func (r *Resolver) useable(addr netip.Addr) (ok bool) {
	r.mu.RLock()
	ok = (r.useIPv4 && addr.Is4()) || (r.useIPv6 && addr.Is6())
	r.mu.RUnlock()
	return
}

func (r *Resolver) authQtypes() (qtypes []uint16) {
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

func (r *Resolver) recurse(ctx context.Context, dialer proxy.ContextDialer, logw io.Writer, depth int, nsaddr netip.Addr, orgqname string, orgqtype uint16, qlabel int) (*dns.Msg, netip.Addr, error) {
	if depth >= maxDepth {
		_ = (logw != nil) && log(logw, depth, "maximum depth reached\n")
		return nil, netip.Addr{}, ErrMaxDepth
	}

	qname := orgqname
	qtype := orgqtype

	idx, final := dns.PrevLabel(qname, qlabel)
	if final = final || idx == 0; !final {
		qtype = dns.TypeNS
		qname = qname[idx:]
	}

	resp, err := r.sendQuery(ctx, dialer, logw, depth, nsaddr, qname, qtype)
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

	if final && len(answer) > 0 {
		_ = (logw != nil) && log(logw, depth, "ANSWER for %s %q: %v\n", DnsTypeToString(qtype), qname, answer)
		return resp, nsaddr, nil
	}

	if len(answer) == 0 {
		var cnameError error
		if len(cnames) > 0 {
			_ = (logw != nil) && log(logw, depth, "CNAMEs for %q: %v\n", qname, cnames)
			for _, cname := range cnames {
				if cmsg, srv, err := r.recurseFromRoot(ctx, dialer, logw, depth+1, cname, orgqtype); err == nil {
					resp.Answer = append(resp.Answer, cmsg.Answer...)
					resp.Ns = nil
					resp.Extra = nil
					return resp, srv, nil
				} else {
					_ = (logw != nil) && log(logw, depth, "error resolving CNAME %q: %v\n", qname, err)
					cnameError = err
				}
			}
		}
		if final && resp.MsgHdr.Authoritative {
			if cnameError != nil {
				return nil, nsaddr, cnameError
			}
			_ = (logw != nil) && log(logw, depth, "authoritative response with no ANSWERs\n")
			return resp, nsaddr, nil
		}
	}

	var authorities []dns.RR
	authoritiesMsg := resp
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
		_ = (logw != nil) && log(logw, depth, "no authoritative NS found for %q, using previous\n", qname)
		return r.recurse(ctx, dialer, logw, depth+1, nsaddr, orgqname, orgqtype, qlabel+1)
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

	authDepthError := false
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

	_ = (logw != nil) && log(logw, depth, "authorities with glue records: %v\n", authWithGlue)
	for _, authority := range authWithGlue {
		for _, authaddr := range gluemap[authority] {
			answers, srv, err := r.recurse(ctx, dialer, logw, depth+1, authaddr, orgqname, orgqtype, qlabel+1)
			switch err {
			case nil, ErrNoResponse:
				return answers, srv, err
			case ErrMaxDepth:
				authDepthError = true
			}
		}
	}

	_ = (logw != nil) && log(logw, depth, "authorities without glue records: %v\n", authWithoutGlue)
	for _, authority := range authWithoutGlue {
		for _, authQtype := range r.authQtypes() {
			authAddrs, _, err := r.recurseFromRoot(ctx, dialer, logw, depth+1, authority, authQtype)
			if authAddrs != nil && len(authAddrs.Answer) > 0 {
				_ = (logw != nil) && log(logw, depth, "resolved authority %s %q to %v\n", DnsTypeToString(authQtype), authority, authAddrs.Answer)
				for _, nsrr := range authAddrs.Answer {
					if authaddr := AddrFromRR(nsrr); authaddr.IsValid() {
						if r.useable(authaddr) {
							answers, srv, err := r.recurse(ctx, dialer, logw, depth+1, authaddr, orgqname, orgqtype, qlabel+1)
							switch err {
							case nil, ErrNoResponse:
								return answers, srv, err
							case ErrMaxDepth:
								authDepthError = true
							}
						}
					}
				}
			} else if err != nil {
				_ = (logw != nil) && log(logw, depth, "error querying authority %q: %v\n", authority, err)
			}
		}
	}
	if authDepthError {
		return nil, nsaddr, ErrMaxDepth
	}
	if final && qtype == dns.TypeNS {
		_ = (logw != nil) && log(logw, depth, "ANSWER with referral NS\n")
		resp = authoritiesMsg.Copy()
		resp.Answer = authorities
		resp.Ns = nil
		resp.Extra = nil
		return resp, nsaddr, nil
	}
	return nil, nsaddr, ErrNoResponse
}

func (r *Resolver) sendQueryUsing(ctx context.Context, timeout time.Duration, dialer proxy.ContextDialer, logw io.Writer, depth int, protocol string, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	if msg = r.cacheget(logw, depth, nsaddr, qname, qtype); msg != nil {
		return
	}

	if !r.useable(nsaddr) {
		return nil, net.ErrClosed
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
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
		log(logw, depth, "sending %s: @%s%s%s %s %q", network, nsaddr, protostr, dash6str, DnsTypeToString(qtype), qname)
	}

	atomic.AddUint64(&r.queryCount, 1)

	var nconn net.Conn
	var rtt time.Duration
	if nconn, err = dialer.DialContext(ctx, network, netip.AddrPortFrom(nsaddr, 53).String()); err == nil {
		dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
		defer dnsconn.Close()
		m := new(dns.Msg)
		m.SetQuestion(qname, qtype)
		m.Compress = true
		m.RecursionDesired = false
		m.SetEdns0(dns.DefaultMsgSize, false)
		c := dns.Client{UDPSize: dns.DefaultMsgSize}
		msg, rtt, err = c.ExchangeWithConnContext(ctx, m, dnsconn)
	}

	ipv6disabled := (err != nil && nsaddr.Is6() && r.maybeDisableIPv6(depth, err))

	if logw != nil {
		if msg != nil {
			fmt.Fprintf(logw, " => %s [%d+%d+%d A/N/E] (%v, %d bytes", dns.RcodeToString[msg.Rcode],
				len(msg.Answer), len(msg.Ns), len(msg.Extra), rtt.Round(time.Millisecond), msg.Len())
			if msg.MsgHdr.Truncated {
				fmt.Fprintf(logw, " truncated")
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

func (r *Resolver) sendQuery(ctx context.Context, dialer proxy.ContextDialer, logw io.Writer, depth int, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	if r.UdpQueryTimeout > 0 {
		msg, err = r.sendQueryUsing(ctx, r.UdpQueryTimeout, dialer, logw, depth, "udp", nsaddr, qname, qtype)
		if msg != nil && msg.MsgHdr.Truncated {
			_ = (logw != nil) && log(logw, depth, "message truncated; retry using TCP\n")
			msg = nil
		}
	}
	if (msg == nil || err != nil) && r.useable(nsaddr) {
		msg, err = r.sendQueryUsing(ctx, r.TcpQueryTimeout, dialer, logw, depth, "tcp", nsaddr, qname, qtype)
	}
	if err == nil {
		r.CacheSet(nsaddr, qname, qtype, msg)
	}
	return
}

func (r *Resolver) maybeDisableIPv6(depth int, err error) (disabled bool) {
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

func (r *Resolver) cacheget(logw io.Writer, depth int, nsaddr netip.Addr, qname string, qtype uint16) *dns.Msg {
	ck := cacheKey{
		nsaddr: nsaddr,
		qname:  qname,
		qtype:  qtype,
	}
	r.mu.RLock()
	cv, ok := r.cache[ck]
	r.mu.RUnlock()
	if ok {
		if time.Since(cv.expires) < 0 {
			_ = (logw != nil) && log(logw, depth, "cache hit: @%s %s %q => %s [%d+%d+%d A/N/E]\n",
				nsaddr, DnsTypeToString(qtype), qname, dns.RcodeToString[cv.Rcode], len(cv.Answer), len(cv.Ns), len(cv.Extra))
			atomic.AddUint64(&r.cacheHits, 1)
			return cv.Msg
		}
		r.mu.Lock()
		delete(r.cache, ck)
		r.mu.Unlock()
	}
	return nil
}

// QueryCount returns the number of queries sent.
func (r *Resolver) QueryCount() uint64 {
	return atomic.LoadUint64(&r.queryCount)
}

// CacheHitRatio returns the hit ratio as a percentage.
func (r *Resolver) CacheHitRatio() float64 {
	qsent := atomic.LoadUint64(&r.queryCount)
	hits := atomic.LoadUint64(&r.cacheHits)
	if total := qsent + hits; total > 0 {
		return float64(hits*100) / float64(total)
	}
	return 0
}

// CacheSize returns the number of entries in the cache.
func (r *Resolver) CacheSize() (n int) {
	r.mu.RLock()
	n = len(r.cache)
	r.mu.RUnlock()
	return
}

func (r *Resolver) CacheSet(nsaddr netip.Addr, qname string, qtype uint16, msg *dns.Msg) {
	if msg != nil && msg.Rcode == dns.RcodeSuccess && !msg.MsgHdr.Truncated {
		ttl := min(MinTTL(msg), maxCacheTTL)
		if ttl < 0 {
			// empty response, cache it for a while
			ttl = maxCacheTTL / 10
		}
		ck := cacheKey{
			nsaddr: nsaddr,
			qname:  qname,
			qtype:  qtype,
		}
		cv := cacheValue{
			Msg:     msg,
			expires: time.Now().Add(time.Duration(ttl) * time.Second),
		}
		r.mu.Lock()
		r.cache[ck] = cv
		r.mu.Unlock()
	}
}

func (r *Resolver) CacheGet(nsaddr netip.Addr, qname string, qtype uint16) *dns.Msg {
	return r.cacheget(nil, 0, nsaddr, qname, qtype)
}

func (r *Resolver) CacheClean(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.IsZero() {
		r.rootIndex = rand.Intn(len(r.rootServers))
	}
	for ck, cv := range r.cache {
		if now.IsZero() || now.After(cv.expires) {
			delete(r.cache, ck)
		}
	}
}
