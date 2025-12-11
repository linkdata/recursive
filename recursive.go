// package recursive provides a minimal iterative DNS resolver with QNAME minimization
// using github.com/miekg/dns for wire format and transport.
package recursive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

//go:generate go run ./cmd/genhints roothints.gen.go

const (
	maxSrvCookies = 8192
	srvCookieTTL  = 24 * time.Hour
	maxDepth      = 16   // max recursion depth
	maxSteps      = 4096 // max steps to take for a query
)

type Recursive struct {
	proxy.ContextDialer                 // context dialer to use
	Cacher                              // cache to use for DnsResolve
	Timeout             time.Duration   // default is DefaultTimeout
	DNSPort             uint16          // default is DefaultDNSPort
	Deterministic       bool            // if true, always query nameservers in the same order
	MsgSize             uint16          // UDP message size
	rateLimiter         <-chan struct{} // (read-only) rate limited passed to NewWithOptions
	mu                  sync.RWMutex    // protects following
	useIPv4             bool
	useIPv6             bool
	useUDP              bool
	rootServers         []netip.Addr
	clicookie           string
	srvcookies          map[netip.Addr]srvCookie
	udperrs             map[netip.Addr]CachedNetError
	tcperrs             map[netip.Addr]CachedNetError
}

func (r *Recursive) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return r.ResolveWithOptions(ctx, r.Cacher, nil, qname, qtype)
}

var _ Resolver = &Recursive{}

var (
	// ErrInvalidCookie is returned if the DNS cookie from the server is invalid.
	ErrInvalidCookie = errors.New("invalid cookie")
	// ErrMismatchedQuestion is returned when a response question does not match the query.
	ErrMismatchedQuestion = errors.New("mismatched response question")
	// ErrMaxDepth is returned when recursive resolving exceeds the allowed limit.
	ErrMaxDepth = errors.New("recursion depth exceeded 16")
	// ErrMaxSteps is returned when resolving exceeds the step limit.
	ErrMaxSteps = errors.New("resolve steps exceeded 4096")
	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	// It is equivalent to SERVFAIL.
	ErrNoResponse = errors.New("no authoritative response")

	DefaultCache          = NewCache()
	DefaultTimeout        = time.Second * 3
	DefaultDNSPort uint16 = 53
	DefaultMsgSize uint16 = 1232 // default UDP message size
)

// NewWithOptions returns a new Recursive resolver using the given ContextDialer and
// using the given Cacher as the cache when calling DnsResolve. It does not call OrderRoots.
//
// Passing nil for dialer will use a net.Dialer.
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

	var roots []netip.Addr
	roots = append(roots, roots4...)
	roots = append(roots, roots6...)

	return &Recursive{
		ContextDialer: dialer,
		Cacher:        cache,
		DNSPort:       DefaultDNSPort,
		Timeout:       DefaultTimeout,
		MsgSize:       DefaultMsgSize,
		rateLimiter:   rateLimiter,
		useUDP:        true,
		useIPv4:       len(roots4) > 0,
		useIPv6:       len(roots6) > 0,
		rootServers:   roots,
		clicookie:     makeCookie(),
		srvcookies:    make(map[netip.Addr]srvCookie),
		udperrs:       make(map[netip.Addr]CachedNetError),
		tcperrs:       make(map[netip.Addr]CachedNetError),
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

// ResolveWithOptions performs iterative resolution with QNAME minimization for qname/qtype.
func (r *Recursive) ResolveWithOptions(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (msg *dns.Msg, origin netip.Addr, err error) {
	now := time.Now()
	r.cleanupSrvCookies(now)
	qry := query{
		Recursive: r,
		cache:     cache,
		logw:      logw,
		start:     now,
		glue:      make(map[string][]netip.Addr),
	}
	msg, origin, err = qry.resolve(ctx, dns.CanonicalName(qname), qtype)
	return
}

// GetRoots returns the current set of root servers in use.
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

func (r *Recursive) setNetError(protocol string, nsaddr netip.Addr, err error) (isIpv6err, isUdpErr bool) {
	if err != nil {
		isIpv6err = nsaddr.Is6()
		var ne net.Error
		ok := errors.Is(err, io.EOF)
		if errors.As(err, &ne) {
			ok = true
		}
		ok = ok || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
		ok = ok || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, net.ErrClosed)
		errstr := err.Error()
		ok = ok || strings.Contains(errstr, "timeout") || strings.Contains(errstr, "refused")
		if ok {
			var m map[netip.Addr]CachedNetError
			switch protocol {
			case "udp":
				isUdpErr = true
				m = r.udperrs
			case "tcp":
				m = r.tcperrs
			}
			if m != nil {
				r.mu.Lock()
				m[nsaddr] = CachedNetError{Err: err, When: time.Now(), Protocol: protocol, Address: nsaddr}
				r.mu.Unlock()
			}
		}
	}
	return
}
