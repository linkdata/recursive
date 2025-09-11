package recursive

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (q *query) exchange(ctx context.Context, nsaddr netip.Addr, qname string, qtype uint16) (*dns.Msg, error) {
	// Try cache first
	if q.cache != nil && !q.nomini {
		if msg := q.cache.DnsGet(qname, qtype); msg != nil {
			if !cacheExtra {
				msg.Extra = nil
			}
			if q.dbg() {
				q.logCachedAnswer(msg, qtype, qname)
			}
			return msg, nil
		}
	}

	useCookies := true

	// Try UDP first if enabled
	if q.usingUDP() {
		msg, err := q.exchangeUsing(ctx, "udp", useCookies, nsaddr, qname, qtype)
		if msg != nil {
			if msg.MsgHdr.Truncated {
				if q.dbg() {
					q.log("message truncated; retry using TCP\n")
				}
				msg = nil
			} else if msg.MsgHdr.Rcode == dns.RcodeFormatError {
				if q.dbg() {
					q.log("got FORMERR, retry using TCP without cookies\n")
				}
				msg = nil
				useCookies = false
			} else {
				return msg, err
			}
		}
	}

	// Fall back to TCP if needed
	if q.useable(nsaddr) {
		return q.exchangeUsing(ctx, "tcp", useCookies, nsaddr, qname, qtype)
	}

	return nil, net.ErrClosed
}

func (q *query) exchangeUsing(ctx context.Context, protocol string, useCookies bool,
	nsaddr netip.Addr, qname string, qtype uint16) (*dns.Msg, error) {

	q.steps++
	if q.steps > maxSteps {
		return nil, ErrMaxSteps
	}

	if err := q.getUsable(ctx, protocol, nsaddr); err != nil {
		return nil, err
	}

	network := q.buildNetwork(protocol, nsaddr)

	if q.rateLimiter != nil {
		<-q.rateLimiter
	}

	if q.dbg() {
		q.logSending(network, protocol, nsaddr, qtype, qname)
	}

	// Set timeout if configured
	if q.Timeout > 0 {
		ctx2, cancel := context.WithTimeout(ctx, q.Timeout)
		defer cancel()
		ctx = ctx2
	}

	// Dial the server
	nconn, err := q.DialContext(ctx, network, netip.AddrPortFrom(nsaddr, dnsPort).String())
	if err != nil {
		q.handleDialError(protocol, nsaddr, err)
		return nil, err
	}

	q.sent++
	dnsconn := &dns.Conn{Conn: nconn, UDPSize: dns.DefaultMsgSize}
	defer dnsconn.Close()

	// Build and send the query
	m := q.buildQuery(qname, qtype, useCookies, nsaddr)

	c := dns.Client{UDPSize: dns.DefaultMsgSize}
	msg, rtt, err := c.ExchangeWithConnContext(ctx, m, dnsconn)

	// Process cookies in response
	if useCookies && msg != nil {
		if err := q.processCookies(msg, nsaddr); err != nil {
			return nil, err
		}
	}

	// Handle network errors and log results
	isIpv6Err, isUdpErr := q.setNetError(protocol, nsaddr, err)
	ipv6disabled := isIpv6Err && q.maybeDisableIPv6(err)
	udpDisabled := isUdpErr && q.maybeDisableUdp(err)

	if q.dbg() {
		q.logResponse(msg, rtt, err, ipv6disabled, udpDisabled)
	}

	return msg, err
}

func (q *query) buildNetwork(protocol string, nsaddr netip.Addr) string {
	if nsaddr.Is4() {
		return protocol + "4"
	}
	return protocol + "6"
}

func (q *query) buildQuery(qname string, qtype uint16, useCookies bool, nsaddr netip.Addr) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(dns.DefaultMsgSize)

	if useCookies {
		clicookie := q.getClientCookie()
		srvcookie, hasSrvCookie := q.getServerCookie(nsaddr)

		if !hasSrvCookie || srvcookie != "" {
			opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
				Code:   dns.EDNS0COOKIE,
				Cookie: clicookie + srvcookie,
			})

			if q.dbg() {
				fmt.Fprintf(q.logw, " COOKIE:c=%q s=%q",
					maskCookie(clicookie), maskCookie(srvcookie))
			}
		}
	}

	m.Extra = append(m.Extra, opt)
	return m
}

func (q *query) processCookies(msg *dns.Msg, nsaddr netip.Addr) error {
	clicookie := q.getClientCookie()
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, rr := range opt.Option {
		cookie, ok := rr.(*dns.EDNS0_COOKIE)
		if !ok {
			continue
		}

		if !strings.HasPrefix(cookie.Cookie, clicookie) {
			return ErrInvalidCookie
		}

		newsrvcookie := strings.TrimPrefix(cookie.Cookie, clicookie)
		q.setServerCookie(nsaddr, newsrvcookie)
	}

	return nil
}

func (q *query) handleDialError(protocol string, nsaddr netip.Addr, err error) {
	isIpv6Err, isUdpErr := q.setNetError(protocol, nsaddr, err)
	q.maybeDisableIPv6(err)
	q.maybeDisableUdp(err)

	if q.dbg() {
		q.log("dial error: %v (ipv6=%v, udp=%v)\n", err, isIpv6Err, isUdpErr)
	}
}

func (q *query) logCachedAnswer(msg *dns.Msg, qtype uint16, qname string) {
	auth := ""
	if msg.MsgHdr.Authoritative {
		auth = " AUTH"
	}
	q.log("cached answer: %s %q => %s [%v+%v+%v A/N/E]%s\n",
		DnsTypeToString(qtype), qname,
		dns.RcodeToString[msg.Rcode],
		len(msg.Answer), len(msg.Ns), len(msg.Extra),
		auth)
}

func (q *query) logSending(network, protocol string, nsaddr netip.Addr, qtype uint16, qname string) {
	var protostr string
	var dash6str string
	if protocol != "udp" {
		protostr = " +" + protocol
	}
	if nsaddr.Is6() {
		dash6str = " -6"
	}
	q.log("SENDING %s: @%s%s%s %s %q", network, nsaddr, protostr, dash6str,
		DnsTypeToString(qtype), qname)
}

func (q *query) logResponse(msg *dns.Msg, rtt time.Duration, err error, ipv6disabled, udpDisabled bool) {
	if msg != nil {
		fmt.Fprintf(q.logw, " => %s [%v+%v+%v A/N/E] (%v, %d bytes",
			dns.RcodeToString[msg.Rcode],
			len(msg.Answer), len(msg.Ns), len(msg.Extra),
			rtt.Round(time.Millisecond), msg.Len())

		if msg.MsgHdr.Truncated {
			fmt.Fprintf(q.logw, " TRNC")
		}
		if msg.MsgHdr.Authoritative {
			fmt.Fprintf(q.logw, " AUTH")
		}

		if opt := msg.IsEdns0(); opt != nil {
			if er := uint16(opt.ExtendedRcode()); er != 0 {
				fmt.Fprintf(q.logw, " EDNS=%s", dns.ExtendedErrorCodeToString[er])
			}
		}
		fmt.Fprintf(q.logw, ")")
	}

	if err != nil {
		fmt.Fprintf(q.logw, " error: %v", err)
	}
	if ipv6disabled {
		fmt.Fprintf(q.logw, " (IPv6 disabled)")
	}
	if udpDisabled {
		fmt.Fprintf(q.logw, " (UDP disabled)")
	}
	fmt.Fprintln(q.logw)
}

func maskCookie(s string) string {
	if len(s) > 8 {
		return s[:8] + "..."
	}
	return s
}
