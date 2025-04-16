package recursive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
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
	NS	wetrgijrotigj.bet.ar
	A	h6xyrckrof16xv31.xn--kprw13d
	MX	3sj82qujmol2npax.us.kg
	A	9ghuun5oshdr6hvi.prd.mg
*/

//go:generate go run ./cmd/genhints roothints.gen.go

const (
	maxDepth        = 32 // maximum recursion depth
	maxRootAttempts = 2  // maximum number of root servers to try
)

var (
	// ErrInvalidCookie is returned if the DNS cookie from the server is invalid.
	ErrInvalidCookie = errors.New("invalid cookie")
	// ErrMaxDepth is returned when recursive resolving exceeds the allowed limit.
	ErrMaxDepth = fmt.Errorf("recursion depth exceeded %d", maxDepth)
	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	// It is equivalent to SERVFAIL.
	ErrNoResponse = errors.New("no authoritative response")
	// ErrQuestionMismatch is returned when the DNS response is not for what was queried.
	ErrQuestionMismatch = errors.New("question mismatch")
	DefaultCache        = NewCache()
	DefaultTimeout      = time.Second * 5
)

var _ Resolver = (*Recursive)(nil) // ensure we implement interface

type Recursive struct {
	proxy.ContextDialer                 // (read-only) ContextDialer passed to NewWithOptions
	Cacher                              // (read-only) Cacher passed to NewWithOptions
	*net.Resolver                       // (read-only) net.Resolver using our ContextDialer
	Timeout             time.Duration   // (read-only) dialing timeout, zero to disable
	rateLimiter         <-chan struct{} // (read-only) rate limited passed to NewWithOptions
	DefaultLogWriter    io.Writer       // if not nil, write debug logs here unless overridden
	mu                  sync.RWMutex    // protects following
	useUDP              bool
	useIPv4             bool
	useIPv6             bool
	rootServers         []netip.Addr
	clicookie           string
	srvcookies          map[netip.Addr]string
	udperrs             map[netip.Addr]netError
	tcperrs             map[netip.Addr]netError
}

func makeCookie() string {
	return fmt.Sprintf("%016x", rand.Uint64()) //#nosec G404
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
		clicookie:   makeCookie(),
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
	r.clicookie = makeCookie()
	clear(r.srvcookies)
}

// OrderRoots sorts the root server list by their current latency and removes those that don't respond.
//
// If ctx does not have a deadline, DefaultTimeout will be used.
func (r *Recursive) OrderRoots(ctx context.Context) {
	if _, ok := ctx.Deadline(); !ok {
		newctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
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

// ResolveWithOptions performs a recursive DNS resolution for the provided name and record type.
//
// If cache is nil, no cache is used. If logw is non-nil (or DefaultLogWriter is set), write a log of events.
func (r *Recursive) ResolveWithOptions(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	if logw == nil {
		logw = r.DefaultLogWriter
	}
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
			var gotname string
			var gottype uint16
			if len(msg.Question) > 0 {
				gotname = msg.Question[0].Name
				gottype = msg.Question[0].Qtype
			}
			if gotname != qname || gottype != qtype {
				err = ErrQuestionMismatch
				_ = q.dbg() && q.log("ERROR: ANSWER was for %s %q, not %s %q\n",
					DnsTypeToString(gottype), gotname,
					DnsTypeToString(qtype), qname,
				)
			}
		} else {
			// NXDOMAIN or other failures may have the returned
			// question refer to some NS in the chain, but we still want
			// to associate the reply with the original query.
			msg.SetQuestion(qname, qtype)
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

// DnsResolve performs a recursive DNS resolution for the provided name and record type.
func (r *Recursive) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return r.ResolveWithOptions(ctx, r, nil, qname, qtype)
}

func (r *Recursive) getRootServers() (nslist []hostAddr) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, addr := range r.rootServers {
		nslist = append(nslist, hostAddr{"root", addr})
	}
	return
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

func (r *Recursive) usingUDP() (yes bool) {
	r.mu.RLock()
	yes = r.useUDP
	r.mu.RUnlock()
	return
}

func (r *Recursive) useable(addr netip.Addr) (ok bool) {
	r.mu.RLock()
	ok = (r.useIPv4 && addr.Is4()) || (r.useIPv6 && addr.Is6())
	r.mu.RUnlock()
	return
}

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

func (r *Recursive) maybeDisableIPv6(err error) (disabled bool) {
	if ne, ok := err.(net.Error); ok {
		if !ne.Timeout() {
			errstr := ne.Error()
			if strings.Contains(errstr, "network is unreachable") || strings.Contains(errstr, "no route to host") {
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
