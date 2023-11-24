package recursive

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

//go:generate go run ./cmd/genhints named.root roothints.gen.go

const (
	maxDepth        = 30  // maximum recursion depth
	maxRootAttempts = 4   // maximum number of root servers to try
	maxCacheTTL     = 600 // longest allowed TTL for the cache
)

var (
	// ErrMaxDepth is returned when recursive resolving exceeds the allowed limit.
	ErrMaxDepth = fmt.Errorf("recursion depth exceeded %d", maxDepth)
	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	// Consider it equivalent to SERVFAIL.
	ErrNoResponse = errors.New("no authoritative response")
	// UdpQueryTimeout is the timeout set on UDP queries before trying TCP.
	// If set to zero, UDP will not be used.
	UdpQueryTimeout = 5 * time.Second
)

var defaultNetDialer net.Dialer

type Resolver struct {
	dialer      proxy.ContextDialer
	logger      *log.Logger
	useIPv4     bool
	useIPv6     bool
	rootServers []netip.Addr
	mu          sync.RWMutex
	cache       map[cacheKey]cacheValue
}

func NewWithOptions(dialer proxy.ContextDialer, roots4, roots6 []netip.Addr, debuglogger *log.Logger) *Resolver {
	if dialer == nil {
		dialer = &defaultNetDialer
	}

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
		dialer:      dialer,
		logger:      debuglogger,
		useIPv4:     root4 != nil,
		useIPv6:     root6 != nil,
		rootServers: roots,
		cache:       make(map[cacheKey]cacheValue),
	}
}

func New() *Resolver {
	return NewWithOptions(nil, Roots4, Roots6, nil)
}

func (r *Resolver) log(format string, args ...any) bool {
	r.logger.Printf(format, args...)
	return false
}

// Resolve will perform a recursive DNS resolution for the provided name and record type,
// starting from a randomly chosen root server.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return r.recurseFromRoot(ctx, rand.Intn(len(r.rootServers)), 0, name, qtype)
}

func (r *Resolver) recurseFromRoot(ctx context.Context, rootidx int, depth int, qname string, qtype uint16) (*dns.Msg, error) {
	var depthError bool
	qname = dns.CanonicalName(qname)

	_ = (r.logger != nil) && r.log("%*sresolving from root %s %q", depth*2, "", DnsTypeToString(qtype), qname)

	for i := 0; i < maxRootAttempts; i++ {
		server := r.rootServers[(rootidx+i)%len(r.rootServers)]
		retv, err := r.recurse(ctx, rootidx, depth, server, qname, qtype)
		switch err {
		case nil:
			return retv, err
		case ErrMaxDepth:
			depthError = true
		}
	}
	if depthError {
		return nil, ErrMaxDepth
	}
	return nil, ErrNoResponse
}

func (r *Resolver) recurse(ctx context.Context, rootidx int, depth int, nsaddr netip.Addr, qname string, qtype uint16) (*dns.Msg, error) {
	if depth >= maxDepth {
		_ = (r.logger != nil) && r.log("%*smaximum depth reached", depth*2, "")
		return nil, ErrMaxDepth
	}

	resp, err := r.sendQuery(ctx, depth, qname, nsaddr, qtype)
	if err != nil {
		return nil, err
	}

	var answers []dns.RR
	var cnames []string
	for _, answer := range resp.Answer {
		if crec, ok := answer.(*dns.CNAME); ok {
			cnames = append(cnames, dns.Fqdn(crec.Target))
			continue
		}
		answers = append(answers, answer)
	}

	var cnameError error
	if len(answers) == 0 {
		_ = (r.logger != nil) && r.log("%*sno answers for %q", depth*2, "", qname)
		if len(cnames) > 0 {
			_ = (r.logger != nil) && r.log("%*sCNAMEs for %q: %v", depth*2, "", qname, cnames)
			for _, cname := range cnames {
				cnamed, err := r.recurseFromRoot(ctx, rootidx, depth+1, cname, qtype)
				switch err {
				case nil:
					return cnamed, nil
				}
				_ = (r.logger != nil) && r.log("%*serror resolving CNAME %q: %v", depth*2, "", qname, err)
				cnameError = err
			}
		}
	}

	if len(answers) > 0 {
		_ = (r.logger != nil) && r.log("%*sANSWER for %s %q: %v", depth*2, "", DnsTypeToString(qtype), qname, answers)
		return resp, nil
	}

	if resp.MsgHdr.Authoritative {
		if cnameError != nil {
			return nil, cnameError
		}
		_ = (r.logger != nil) && r.log("%*sauthoritative response with no ANSWERs", depth*2, "")
		return resp, nil
	}

	_ = (r.logger != nil) && r.log("%*s%d NS and %d EXTRA for %s %q", depth*2, "", len(resp.Ns), len(resp.Extra), DnsTypeToString(qtype), qname)

	var authorities []dns.RR
	authoritiesMsg := resp
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			authorities = append(authorities, ns)
		}
	}

	gluemap := make(map[string][]netip.Addr)
	for _, rr := range resp.Extra {
		if addr := AddrFromRR(rr); addr.IsValid() {
			if (r.useIPv4 && addr.Is4()) || (r.useIPv6 && addr.Is6()) {
				gluename := dns.CanonicalName(rr.Header().Name)
				gluemap[gluename] = append(gluemap[gluename], addr)
			}
		} else {
			_ = (r.logger != nil) && r.log("%*sunexpected RR (%T)%v", depth*2, "", rr, rr)
		}
	}

	var authWithGlue, authWithoutGlue []string

	for _, nsrr := range authorities {
		if nsrr, ok := nsrr.(*dns.NS); ok {
			gluename := dns.CanonicalName(nsrr.Ns)
			if len(gluemap[gluename]) > 0 {
				authWithGlue = append(authWithGlue, nsrr.Ns)
			} else {
				authWithoutGlue = append(authWithoutGlue, nsrr.Ns)
			}
		}
	}

	authDepthError := false
	_ = (r.logger != nil) && r.log("%*sauthorities with glue records: %v", depth*2, "", authWithGlue)
	for _, authority := range authWithGlue {
		for _, authaddr := range gluemap[authority] {
			answers, err := r.recurse(ctx, rootidx, depth+1, authaddr, qname, qtype)
			switch err {
			case nil:
				return answers, nil
			case ErrMaxDepth:
				authDepthError = true
			}
		}
	}

	_ = (r.logger != nil) && r.log("%*sauthorities without glue records: %v", depth*2, "", authWithoutGlue)
	for _, authority := range authWithoutGlue {
		var authQtypes []uint16
		if r.useIPv4 {
			authQtypes = append(authQtypes, dns.TypeA)
		}
		if r.useIPv6 {
			authQtypes = append(authQtypes, dns.TypeAAAA)
		}
		for _, authQtype := range authQtypes {
			authAddrs, err := r.recurseFromRoot(ctx, rootidx, depth+1, authority, authQtype)
			if authAddrs != nil && len(authAddrs.Answer) > 0 {
				_ = (r.logger != nil) && r.log("%*sresolved authority %s %q to %v", depth*2, "", DnsTypeToString(authQtype), authority, authAddrs.Answer)
				for _, nsrr := range authAddrs.Answer {
					if authaddr := AddrFromRR(nsrr); authaddr.IsValid() {
						if (r.useIPv4 && authaddr.Is4()) || (r.useIPv6 && authaddr.Is6()) {
							answer, err := r.recurse(ctx, rootidx, depth+1, authaddr, qname, qtype)
							switch err {
							case nil:
								return answer, nil
							case ErrMaxDepth:
								authDepthError = true
							}
						}
					}
				}
			} else if err != nil {
				_ = (r.logger != nil) && r.log("%*serror querying authority %q: %v", depth*2, "", authority, err)
			}
		}
	}

	if authDepthError {
		return nil, ErrMaxDepth
	}
	if qtype == dns.TypeNS && len(authorities) > 0 {
		return authoritiesMsg, nil
	}
	return nil, ErrNoResponse
}

func (r *Resolver) sendQueryUsing(ctx context.Context, depth int, protocol string, nsaddr netip.Addr, qname string, qtype uint16) (msg *dns.Msg, err error) {
	if msg = r.cacheget(depth, nsaddr, qname, qtype); msg != nil {
		return
	}

	if r.logger != nil {
		var protostr string
		var dash6str string
		if protocol != "udp" {
			protostr = " +" + protocol
		}
		if nsaddr.Is6() {
			dash6str = " -6"
		}
		r.logger.Printf("%*ssending query @%s%s%s %s %s", depth*2, "",
			nsaddr, protostr, dash6str, DnsTypeToString(qtype), qname)
	}

	var network string
	if nsaddr.Is4() {
		network = protocol + "4"
	} else {
		network = protocol + "6"
	}

	var nconn net.Conn
	if nconn, err = r.dialer.DialContext(ctx, network, netip.AddrPortFrom(nsaddr, 53).String()); err == nil {
		dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
		defer dnsconn.Close()
		m := new(dns.Msg)
		m.SetQuestion(qname, qtype)
		var c dns.Client
		if msg, _, err = c.ExchangeWithConnContext(ctx, m, dnsconn); err == nil {
			if msg.MsgHdr.Truncated && protocol == "udp" {
				_ = (r.logger != nil) && r.log("%*smessage truncated; retry using TCP", depth*2, "")
				return r.sendQueryUsing(ctx, depth, "tcp", nsaddr, qname, qtype)
			}
			r.CacheSet(nsaddr, qname, qtype, msg)
		}
	}
	return
}

func (r *Resolver) sendQuery(ctx context.Context, depth int, qname string, nsaddr netip.Addr, qtype uint16) (msg *dns.Msg, err error) {
	if UdpQueryTimeout > 0 {
		udpCtx, udpCtxCancel := context.WithTimeout(ctx, UdpQueryTimeout)
		defer udpCtxCancel()
		if msg, err = r.sendQueryUsing(udpCtx, depth, "udp", nsaddr, qname, qtype); err == nil {
			return
		}
	}
	return r.sendQueryUsing(ctx, depth, "tcp", nsaddr, qname, qtype)
}

func (r *Resolver) cacheget(depth int, nsaddr netip.Addr, qname string, qtype uint16) *dns.Msg {
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
			_ = (r.logger != nil) && r.log("%*scache hit: @%s %s %q", depth*2, "", nsaddr, DnsTypeToString(qtype), qname)
			return cv.Msg
		}
		r.mu.Lock()
		delete(r.cache, ck)
		r.mu.Unlock()
	}
	return nil
}

func (r *Resolver) CacheSet(nsaddr netip.Addr, qname string, qtype uint16, msg *dns.Msg) {
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

func (r *Resolver) CacheGet(nsaddr netip.Addr, qname string, qtype uint16) *dns.Msg {
	return r.cacheget(0, nsaddr, qname, qtype)
}

func (r *Resolver) CacheClean(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ck, cv := range r.cache {
		if now.After(cv.expires) {
			delete(r.cache, ck)
		}
	}
}
