package recursive

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	rand "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

//go:generate go run ./cmd/genhints roothints.gen.go

const (
	maxDepth      = 32   // maximum recursion depth
	maxSteps      = 1000 // max number of steps to allow in resolving
	maxSrvCookies = 8192
	srvCookieTTL  = 24 * time.Hour
)

var (
	// ErrInvalidCookie is returned if the DNS cookie from the server is invalid.
	ErrInvalidCookie = errors.New("invalid cookie")
	// ErrMaxDepth is returned when recursive resolving exceeds the allowed limit.
	ErrMaxDepth = fmt.Errorf("recursion depth exceeded %d", maxDepth)
	// ErrMaxSteps is returned when resolving exceeds the step limit.
	ErrMaxSteps = fmt.Errorf("resolve steps exceeded %d", maxSteps)
	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	// It is equivalent to SERVFAIL.
	ErrNoResponse = errors.New("no authoritative response")
	// ErrQuestionMismatch is returned when the DNS response is not for what was queried.
	ErrQuestionMismatch = errors.New("question mismatch")

	DefaultCache   = NewCache()
	DefaultTimeout = time.Second * 5
)

var _ Resolver = (*Recursive)(nil) // ensure we implement interface

// Recursive is a recursive DNS resolver with optional caching and QNAME minimization.
type Recursive struct {
	proxy.ContextDialer                 // (read-only) ContextDialer passed to NewWithOptions
	Cacher                              // (read-only) Cacher passed to NewWithOptions
	*net.Resolver                       // (read-only) net.Resolver using our ContextDialer
	Timeout             time.Duration   // (read-only) dialing timeout, zero to disable
	rateLimiter         <-chan struct{} // (read-only) rate limited passed to NewWithOptions
	DefaultLogWriter    io.Writer       // if not nil, write debug logs here unless overridden

	mu         sync.RWMutex
	config     resolverConfig
	cookies    cookieManager
	netErrors  networkErrors
	dnsResolve func(context.Context, string, uint16) (*dns.Msg, netip.Addr, error)
}

type resolverConfig struct {
	useUDP      bool
	useIPv4     bool
	useIPv6     bool
	rootServers []netip.Addr
}

type cookieManager struct {
	clientCookie  string
	serverCookies map[netip.Addr]srvCookie
}

type networkErrors struct {
	udpErrors map[netip.Addr]netError
	tcpErrors map[netip.Addr]netError
}

type srvCookie struct {
	value string
	ts    time.Time
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

	roots := prepareRootServers(roots4, roots6)

	r := &Recursive{
		ContextDialer: dialer,
		Cacher:        cache,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     dialer.DialContext,
		},
		Timeout:     DefaultTimeout,
		rateLimiter: rateLimiter,
		config: resolverConfig{
			useUDP:      true,
			useIPv4:     len(roots4) > 0 || (roots4 == nil && len(Roots4) > 0),
			useIPv6:     len(roots6) > 0 || (roots6 == nil && len(Roots6) > 0),
			rootServers: roots,
		},
		cookies: cookieManager{
			clientCookie:  makeCookie(),
			serverCookies: make(map[netip.Addr]srvCookie),
		},
		netErrors: networkErrors{
			udpErrors: make(map[netip.Addr]netError),
			tcpErrors: make(map[netip.Addr]netError),
		},
	}
	r.dnsResolve = r.DnsResolve
	return r
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
	r.cookies.clientCookie = makeCookie()
	clear(r.cookies.serverCookies)
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

	rootRtts := r.measureRootLatencies(ctx)
	r.updateRootServers(rootRtts)
}

// GetRoots returns the current set of root servers in use.
func (r *Recursive) GetRoots() (root4, root6 []netip.Addr) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, addr := range r.config.rootServers {
		if addr.Is4() {
			root4 = append(root4, addr)
		} else if addr.Is6() {
			root6 = append(root6, addr)
		}
	}
	return
}

// DnsResolve performs a recursive DNS resolution for the provided name and record type.
func (r *Recursive) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return r.ResolveWithOptions(ctx, r, nil, qname, qtype)
}

// ResolveWithOptions performs a recursive DNS resolution for the provided name and record type.
//
// If cache is nil, no cache is used; nil caches are supported without crashing.
// If logw is non-nil (or DefaultLogWriter is set), write a log of events.
func (r *Recursive) ResolveWithOptions(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	if logw == nil {
		logw = r.DefaultLogWriter
	}

	r.cleanupServerCookies(time.Now())
	qname = dns.CanonicalName(qname)

	// Try cache first
	if cache != nil {
		msg = cache.DnsGet(qname, qtype)
	}

	// If not in cache, perform recursive resolution
	if msg == nil {
		q := &query{
			Recursive: r,
			cache:     cache,
			start:     time.Now(),
			logw:      logw,
			glue:      make(map[string][]netip.Addr),
		}
		msg, srv, err = q.run(ctx, qname, qtype)
	}

	// Validate and cache the response
	if msg != nil {
		err = r.validateResponse(msg, qname, qtype, q)
		if err == nil && cache != nil {
			cache.DnsSet(msg)
		}
	}

	// Log the results if requested
	if logw != nil {
		r.logResults(logw, msg, srv, err, q)
	}

	return
}

// Helper methods

func prepareRootServers(roots4, roots6 []netip.Addr) []netip.Addr {
	if roots4 == nil {
		roots4 = Roots4
	}
	if roots6 == nil {
		roots6 = Roots6
	}

	var root4, root6 []netip.Addr
	if len(roots4) > 0 {
		root4 = append(root4, roots4...)
		shuffleAddrs(root4)
	}
	if len(roots6) > 0 {
		root6 = append(root6, roots6...)
		shuffleAddrs(root6)
	}

	// Interleave IPv4 and IPv6 addresses
	roots := make([]netip.Addr, 0, len(root4)+len(root6))
	n := min(len(root4), len(root6))
	for i := 0; i < n; i++ {
		roots = append(roots, root4[i], root6[i])
	}
	roots = append(roots, root4[n:]...)
	roots = append(roots, root6[n:]...)

	return roots
}

func makeCookie() string {
	b := make([]byte, 8)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

func shuffleAddrs(a []netip.Addr) {
	rand.Shuffle(len(a), func(i, j int) {
		a[i], a[j] = a[j], a[i]
	})
}

func (r *Recursive) measureRootLatencies(ctx context.Context) []*rootRtt {
	var l []*rootRtt
	var wg sync.WaitGroup

	for _, addr := range r.config.rootServers {
		rt := &rootRtt{addr: addr}
		l = append(l, rt)
		wg.Add(1)
		go timeRoot(ctx, r, &wg, rt)
	}
	wg.Wait()

	sort.Slice(l, func(i, j int) bool { return l[i].rtt < l[j].rtt })
	return l
}

func (r *Recursive) updateRootServers(rootRtts []*rootRtt) {
	var newRootServers []netip.Addr
	useIPv4 := false
	useIPv6 := false

	for _, rt := range rootRtts {
		if rt.rtt < time.Minute {
			useIPv4 = useIPv4 || rt.addr.Is4()
			useIPv6 = useIPv6 || rt.addr.Is6()
			newRootServers = append(newRootServers, rt.addr)
		}
	}

	if len(newRootServers) > 0 {
		r.config.rootServers = newRootServers
		r.config.useIPv4 = useIPv4
		r.config.useIPv6 = useIPv6
	}
}

func (r *Recursive) validateResponse(msg *dns.Msg, qname string, qtype uint16, q *query) error {
	if msg.Rcode == dns.RcodeSuccess {
		// A SUCCESS reply must reference the correct QNAME and QTYPE.
		var gotname string
		var gottype uint16
		if len(msg.Question) > 0 {
			gotname = msg.Question[0].Name
			gottype = msg.Question[0].Qtype
		}
		if gotname != qname || gottype != qtype {
			if q != nil && q.dbg() {
				q.log("ERROR: ANSWER was for %s %q, not %s %q\n",
					DnsTypeToString(gottype), gotname,
					DnsTypeToString(qtype), qname,
				)
			}
			return ErrQuestionMismatch
		}
	} else {
		if !msg.Zero {
			// NXDOMAIN or other failures may have the returned
			// question refer to some NS in the chain, but we still want
			// to associate the reply with the original query.
			msg.SetQuestion(qname, qtype)
		}
	}
	return nil
}

func (r *Recursive) logResults(logw io.Writer, msg *dns.Msg, srv netip.Addr, err error, q *query) {
	if msg != nil {
		fmt.Fprintf(logw, "\n%v", msg)
	}
	if q != nil {
		fmt.Fprintf(logw, "\n;; Sent %v queries in %v", q.sent, time.Since(q.start).Round(time.Millisecond))
	}
	if srv.IsValid() {
		fmt.Fprintf(logw, "\n;; SERVER: %v", srv)
	}
	if err != nil {
		fmt.Fprintf(logw, "\n;; ERROR: %v", err)
	}
	fmt.Fprintln(logw)
}

func (r *Recursive) getRootServers() (nslist []hostAddr) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, addr := range r.config.rootServers {
		nslist = append(nslist, hostAddr{"root", addr})
	}
	return
}

func (r *Recursive) usingUDP() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.config.useUDP
}

func (r *Recursive) useable(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	if *msg == nil {
		if q.dbg() {
			q.log("all nameservers returned SERVFAIL\n")
		}
		q.setCache(gotmsg)
		*msg = gotmsg
	}

	return true
}

func (q *query) resolveFinal(ctx context.Context, nslist []hostAddr,
	qname string, qtype uint16, msg *dns.Msg) (*dns.Msg, netip.Addr, error) {

	// Collect all nameserver addresses
	nsaddrs := q.collectNameserverAddresses(nslist)

	if q.dbg() {
		q.logFinalNameservers(nsaddrs)
	}

	// Query final nameservers
	for _, nsaddr := range nsaddrs {
		finalmsg, err := q.exchange(ctx, nsaddr, qname, qtype)
		if err != nil {
			if q.dbg() {
				q.log("FAILED @%v %s %q: %v\n", nsaddr, DnsTypeToString(qtype), qname, err)
			}
			continue
		}

		if finalmsg.Rcode == dns.RcodeServerFailure {
			continue
		}

		msg = finalmsg
		q.setCache(msg)

		// Handle CNAME responses
		if qtype != dns.TypeCNAME {
			if cnameMsg := q.followCNAMEs(ctx, msg, qname, qtype); cnameMsg != nil {
				return cnameMsg, nsaddr, nil
			}
		}

		return msg, nsaddr, nil
	}

	// All final nameservers failed
	if len(nsaddrs) == 0 || (qtype != dns.TypeNS || qname != msg.Question[0].Name) {
		return nil, netip.Addr{}, nil
	}

	return msg, netip.Addr{}, nil
}

func (q *query) collectNameserverAddresses(nslist []hostAddr) []netip.Addr {
	var nsaddrs []netip.Addr
	for _, ha := range nslist {
		if ha.addr.IsValid() {
			nsaddrs = append(nsaddrs, ha.addr)
		} else {
			nsaddrs = append(nsaddrs, q.glue[ha.host]...)
		}
	}

	slices.SortFunc(nsaddrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(nsaddrs)
}

func (q *query) followCNAMEs(ctx context.Context, msg *dns.Msg, qname string, qtype uint16) *dns.Msg {
	for _, rr := range msg.Answer {
		cn, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}

		target := dns.CanonicalName(cn.Target)
		if !q.followCNAME(target) {
			continue
		}

		if q.dbg() {
			q.log("CNAME QUERY %q => %q\n", qname, target)
		}

		cnmsg, _, cnerr := q.run(ctx, target, qtype)
		if cnerr != nil {
			if q.dbg() {
				q.log("CNAME ERROR %q: %v\n", target, cnerr)
			}
			continue
		}

		if q.dbg() {
			q.log("CNAME ANSWER %s %q with %v records\n",
				dns.RcodeToString[cnmsg.Rcode], target, len(cnmsg.Answer))
		}

		result := msg.Copy()
		result.Zero = true
		result.Answer = append(result.Answer, cnmsg.Answer...)
		result.Rcode = cnmsg.Rcode
		return result
	}

	return nil
}

func (q *query) logQuery(final bool, qtype uint16, qname string, nslist []hostAddr) {
	var finaltext string
	if final {
		finaltext = " FINAL"
	}
	maxShow := min(4, len(nslist))
	q.log("QUERY%s %s %q from %v\n", finaltext, DnsTypeToString(qtype), qname, nslist[:maxShow])
}

func (q *query) logFinalNameservers(nsaddrs []netip.Addr) {
	q.log("final nameservers: %v\n", nsaddrs)
	if q.depth == 1 {
		keys := slices.Collect(maps.Keys(q.glue))
		slices.Sort(keys)
		for _, k := range keys {
			q.log("glue: %q: %v\n", k, q.glue[k])
		}
	}
}

// Helper methods for query

func (q *query) dbg() bool {
	return q.logw != nil
}

func (q *query) log(format string, args ...any) bool {
	fmt.Fprintf(q.logw, "[%-5d %2d] %*s", time.Since(q.start).Milliseconds(), q.depth, q.depth, "")
	fmt.Fprintf(q.logw, format, args...)
	return false
}

func (q *query) dive() error {
	if q.depth >= maxDepth {
		return ErrMaxDepth
	}
	q.depth++
	return nil
}

func (q *query) surface() {
	q.depth--
}

func (q *query) needGlue(host string) bool {
	if _, ok := q.glue[host]; !ok {
		q.glue[host] = nil
		return true
	}
	return false
}

func (q *query) addGlue(host string, addr netip.Addr) {
	if !q.useable(addr) {
		return
	}

	addrs, ok := q.glue[host]
	if !ok {
		return
	}

	if !slices.Contains(addrs, addr) {
		q.glue[host] = append(addrs, addr)
	}
}

func (q *query) setCache(msg *dns.Msg) {
	if msg == nil || msg.Zero || q.cache == nil || q.nomini {
		return
	}
	q.cache.DnsSet(msg)
}

func (q *query) glueTypes() []uint16 {
	var gt []uint16
	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.config.useIPv4 {
		gt = append(gt, dns.TypeA)
	}
	if q.config.useIPv6 {
		gt = append(gt, dns.TypeAAAA)
	}
	return gt
}

func (q *query) followCNAME(cn string) bool {
	if q.cnames == nil {
		q.cnames = make(map[string]struct{})
	}

	if _, exists := q.cnames[cn]; exists {
		return false
	}

	q.cnames[cn] = struct{}{}
	return true
}

func (q *query) extractNS(msg *dns.Msg) []hostAddr {
	nsmap := make(map[string]struct{})

	// Extract NS records
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range rrs {
			if ns, ok := rr.(*dns.NS); ok {
				host := dns.CanonicalName(ns.Ns)
				nsmap[host] = struct{}{}
			}

			// Also collect glue records
			host, addr := rrHostAddr(rr)
			if host != "" {
				q.addGlue(host, addr)
			}
		}
	}

	// Process Extra section for glue
	for _, rr := range msg.Extra {
		host, addr := rrHostAddr(rr)
		if _, ok := nsmap[host]; ok {
			q.needGlue(host)
			q.addGlue(host, addr)
		}
	}

	// Build host address list
	var hal []hostAddr
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

	// Make the NS query order deterministic
	slices.SortFunc(hal, compareHostAddr)

	return hal
}

func compareHostAddr(a, b hostAddr) int {
	// Prefer addresses with IPs
	if a.addr.IsValid() {
		if b.addr.IsValid() {
			return a.addr.Compare(b.addr)
		}
		return -1
	}
	if b.addr.IsValid() {
		return 1
	}

	// Sort by label count, then alphabetically
	n := strings.Count(a.host, ".") - strings.Count(b.host, ".")
	if n == 0 {
		n = strings.Compare(a.host, b.host)
	}
	return n
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
