package recursive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// exchangeManager handles DNS message exchanges with servers
type exchangeManager struct {
	recursive *Recursive
	context   *queryContext
}

// newExchangeManager creates a new DNS exchange manager
func newExchangeManager(r *Recursive, qc *queryContext) *exchangeManager {
	return &exchangeManager{
		recursive: r,
		context:   qc,
	}
}

// performDNSQuery executes a DNS query against a specific server
func (qc *queryContext) performDNSQuery(ctx context.Context, serverAddr netip.Addr, qname string, qtype uint16) (*dns.Msg, error) {
	if err := qc.incrementSteps(); err != nil {
		return nil, err
	}
	
	// Check cache first (if not disabled by minimization)
	if qc.cache != nil && !qc.disableMinimization {
		if cachedMsg := qc.cache.DnsGet(qname, qtype); cachedMsg != nil {
			qc.logCacheHit(cachedMsg, qname, qtype)
			return cachedMsg, nil
		}
	}
	
	// Check if server is usable
	if err := qc.recursive.networkErrors.isAddressUsable("udp", serverAddr); err != nil {
		return nil, fmt.Errorf("server %v not usable: %w", serverAddr, err)
	}
	
	em := newExchangeManager(qc.recursive, qc)
	
	// Try UDP first if enabled
	var response *dns.Msg
	var err error
	
	if qc.recursive.canUseUDP() {
		response, err = em.executeQuery(ctx, "udp", serverAddr, qname, qtype, true)
		if response != nil && (response.MsgHdr.Truncated || response.MsgHdr.Rcode == dns.RcodeFormatError) {
			qc.logMessage("message truncated or format error, retrying with TCP\n")
			response = nil // Force TCP retry
		}
	}
	
	// Try TCP if UDP failed or was truncated
	if response == nil && qc.recursive.isAddressUsable(serverAddr) {
		useCookies := err == nil || !errors.Is(err, ErrInvalidCookie)
		response, err = em.executeQuery(ctx, "tcp", serverAddr, qname, qtype, useCookies)
	}
	
	return response, err
}

// executeQuery performs the actual DNS query with the specified protocol
func (em *exchangeManager) executeQuery(ctx context.Context, protocol string, serverAddr netip.Addr, qname string, qtype uint16, useCookies bool) (*dns.Msg, error) {
	// Apply rate limiting if configured
	if em.recursive.rateLimiter != nil {
		select {
		case <-em.recursive.rateLimiter:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	// Prepare network parameters
	network := em.getNetworkString(protocol, serverAddr)
	target := FormatAddressPort(serverAddr, DefaultDNSPort)
	
	// Log query attempt
	em.logQueryAttempt(network, serverAddr, qname, qtype)
	
	// Apply timeout if configured
	queryCtx := ctx
	if em.recursive.Timeout > 0 {
		var cancel context.CancelFunc
		queryCtx, cancel = context.WithTimeout(ctx, em.recursive.Timeout)
		defer cancel()
	}
	
	// Establish connection
	conn, err := em.recursive.DialContext(queryCtx, network, target)
	if err != nil {
		return nil, em.handleNetworkError(protocol, serverAddr, "dial", err)
	}
	defer conn.Close()
	
	// Execute DNS exchange
	startTime := time.Now()
	em.context.queriesSent++
	
	dnsConn := &dns.Conn{Conn: conn, UDPSize: dns.DefaultMsgSize}
	message := em.prepareDNSMessage(qname, qtype, useCookies, serverAddr)
	
	client := dns.Client{UDPSize: dns.DefaultMsgSize}
	response, rtt, err := client.ExchangeWithConnContext(queryCtx, message, dnsConn)
	
	if err != nil {
		return nil, em.handleNetworkError(protocol, serverAddr, "exchange", err)
	}
	
	// Process response and handle cookies
	if response != nil && useCookies {
		em.processCookieResponse(response, serverAddr)
	}
	
	// Log response details
	em.logQueryResponse(response, rtt, serverAddr, time.Since(startTime))
	
	return response, nil
}

// prepareDNSMessage creates a DNS query message with optional cookies
func (em *exchangeManager) prepareDNSMessage(qname string, qtype uint16, useCookies bool, serverAddr netip.Addr) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	
	// Add EDNS0 OPT record
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	opt.SetUDPSize(dns.DefaultMsgSize)
	
	// Add DNS cookie if requested
	if useCookies {
		em.addDNSCookie(opt, serverAddr)
	}
	
	msg.Extra = append(msg.Extra, opt)
	return msg
}

// addDNSCookie adds a DNS cookie to the OPT record
func (em *exchangeManager) addDNSCookie(opt *dns.OPT, serverAddr netip.Addr) {
	clientCookie := em.getClientCookie()
	serverCookie, hasServerCookie := em.recursive.getServerCookie(serverAddr)
	
	// Only add cookie if we don't have a server cookie or we have one to send
	if !hasServerCookie || serverCookie != "" {
		cookieOption := &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: clientCookie + serverCookie,
		}
		opt.Option = append(opt.Option, cookieOption)
		
		// Log cookie usage
		if em.context.shouldLog() {
			fmt.Fprintf(em.context.logWriter, " COOKIE:c=%q s=%q", 
				MaskCookie(clientCookie), MaskCookie(serverCookie))
		}
	}
}

// processCookieResponse processes DNS cookie from response
func (em *exchangeManager) processCookieResponse(response *dns.Msg, serverAddr netip.Addr) {
	clientCookie := em.getClientCookie()
	currentServerCookie, _ := em.recursive.getServerCookie(serverAddr)
	
	if optRecord := response.IsEdns0(); optRecord != nil {
		for _, option := range optRecord.Option {
			if cookieOpt, ok := option.(*dns.EDNS0_COOKIE); ok {
				if strings.HasPrefix(cookieOpt.Cookie, clientCookie) {
					newServerCookie := strings.TrimPrefix(cookieOpt.Cookie, clientCookie)
					if newServerCookie != currentServerCookie {
						em.recursive.setServerCookie(serverAddr, newServerCookie)
					}
				} else {
					// Invalid cookie - this is an error condition
					response = nil
					return
				}
			}
		}
	}
}

// getClientCookie retrieves the current client cookie
func (em *exchangeManager) getClientCookie() string {
	em.recursive.mu.RLock()
	defer em.recursive.mu.RUnlock()
	return em.recursive.clientCookie
}

// getNetworkString returns the appropriate network string for the connection
func (em *exchangeManager) getNetworkString(protocol string, addr netip.Addr) string {
	if addr.Is4() {
		return protocol + "4"
	}
	return protocol + "6"
}

// handleNetworkError processes and records network errors
func (em *exchangeManager) handleNetworkError(protocol string, addr netip.Addr, operation string, err error) error {
	isIPv6, isUDP := em.recursive.networkErrors.recordError(protocol, addr, operation, err)
	
	// Try to disable problematic protocols
	ipv6Disabled := isIPv6 && em.tryDisableIPv6(err)
	udpDisabled := isUDP && em.tryDisableUDP(err)
	
	// Log protocol changes
	if em.context.shouldLog() {
		if ipv6Disabled {
			fmt.Fprintf(em.context.logWriter, " (IPv6 disabled)")
		}
		if udpDisabled {
			fmt.Fprintf(em.context.logWriter, " (UDP disabled)")
		}
	}
	
	return NewNetworkError(addr, protocol, operation, err)
}

// tryDisableIPv6 attempts to disable IPv6 if errors suggest network issues
func (em *exchangeManager) tryDisableIPv6(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for IPv6 connectivity issues
	errorPatterns := []string{
		"network is unreachable",
		"no route to host",
		"address family not supported",
	}
	
	errStr := strings.ToLower(err.Error())
	for _, pattern := range errorPatterns {
		if strings.Contains(errStr, pattern) {
			return em.disableIPv6Protocol()
		}
	}
	
	return false
}

// tryDisableUDP attempts to disable UDP if errors suggest protocol issues
func (em *exchangeManager) tryDisableUDP(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for UDP protocol issues (but not timeouts)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false // Don't disable UDP for timeouts
	}
	
	errorPatterns := []string{
		"protocol not supported",
		"network not implemented",
	}
	
	errStr := strings.ToLower(err.Error())
	for _, pattern := range errorPatterns {
		if strings.Contains(errStr, pattern) {
			return em.disableUDPProtocol()
		}
	}
	
	return false
}

// disableIPv6Protocol disables IPv6 support in the resolver
func (em *exchangeManager) disableIPv6Protocol() bool {
	em.recursive.mu.Lock()
	defer em.recursive.mu.Unlock()
	
	if !em.recursive.config.useIPv6 {
		return false // Already disabled
	}
	
	em.recursive.config.useIPv6 = false
	
	// Remove IPv6 addresses from root servers
	filteredRoots := make([]netip.Addr, 0)
	for _, addr := range em.recursive.config.rootServers {
		if addr.Is4() {
			filteredRoots = append(filteredRoots, addr)
		}
	}
	em.recursive.config.rootServers = filteredRoots
	
	return true
}

// disableUDPProtocol disables UDP support in the resolver
func (em *exchangeManager) disableUDPProtocol() bool {
	em.recursive.mu.Lock()
	defer em.recursive.mu.Unlock()
	
	if !em.recursive.config.useUDP {
		return false // Already disabled
	}
	
	em.recursive.config.useUDP = false
	return true
}

// Logging methods

// logQueryAttempt logs the start of a DNS query
func (em *exchangeManager) logQueryAttempt(network string, addr netip.Addr, qname string, qtype uint16) {
	if !em.context.shouldLog() {
		return
	}
	
	protocolInfo := ""
	if !strings.HasSuffix(network, "udp4") {
		protocolInfo = " +" + strings.TrimSuffix(network, "4")
		protocolInfo = strings.TrimSuffix(protocolInfo, "6")
	}
	
	ipVersionInfo := ""
	if addr.Is6() {
		ipVersionInfo = " -6"
	}
	
	em.context.logMessage("SENDING %s: @%s%s%s %s %q",
		network, addr, protocolInfo, ipVersionInfo, DnsTypeToString(qtype), qname)
}

// logQueryResponse logs the DNS query response details
func (em *exchangeManager) logQueryResponse(response *dns.Msg, rtt time.Duration, addr netip.Addr, totalTime time.Duration) {
	if !em.context.shouldLog() {
		return
	}
	
	if response != nil {
		fmt.Fprintf(em.context.logWriter, " => %s %s (%s, %s",
			GetResponseCode(response), // Use utility function
			GetRecordSummary(response), // Use utility function  
			FormatDuration(rtt), FormatByteCount(response.Len()))
		
		if IsTruncatedResponse(response) { // Use utility function
			fmt.Fprintf(em.context.logWriter, " TRUNC")
		}
		if IsAuthoritativeAnswer(response) { // Use utility function
			fmt.Fprintf(em.context.logWriter, " AUTH")
		}
		
		// Log EDNS extended error codes using miekg/dns utilities
		if opt := response.IsEdns0(); opt != nil {
			if extendedRcode := uint16(opt.ExtendedRcode()); extendedRcode != 0 {
				if errString, ok := dns.ExtendedErrorCodeToString[extendedRcode]; ok {
					fmt.Fprintf(em.context.logWriter, " EDNS=%s", errString)
				}
			}
		}
		
		fmt.Fprintf(em.context.logWriter, ")")
	}
	
	fmt.Fprintln(em.context.logWriter)
}%d A/N/E] (%s, %s",
			dns.RcodeToString[response.Rcode],
			len(response.Answer), len(response.Ns), len(response.Extra),
			FormatDuration(rtt), FormatByteCount(response.Len()))
		
		if response.MsgHdr.Truncated {
			fmt.Fprintf(em.context.logWriter, " TRUNC")
		}
		if response.MsgHdr.Authoritative {
			fmt.Fprintf(em.context.logWriter, " AUTH")
		}
		
		// Log EDNS extended error codes
		if opt := response.IsEdns0(); opt != nil {
			if extendedRcode := uint16(opt.ExtendedRcode()); extendedRcode != 0 {
				fmt.Fprintf(em.context.logWriter, " EDNS=%s", dns.ExtendedErrorCodeToString[extendedRcode])
			}
		}
		
		fmt.Fprintf(em.context.logWriter, ")")
	}
	
	fmt.Fprintln(em.context.logWriter)
}

// logCacheHit logs when a response is served from cache
func (qc *queryContext) logCacheHit(msg *dns.Msg, qname string, qtype uint16) {
	if !qc.shouldLog() {
		return
	}
	
	authInfo := ""
	if msg.MsgHdr.Authoritative {
		authInfo = " AUTH"
	}
	
	qc.logMessage("cached answer: %s %q => %s [%d+%d+%d A/N/E]%s\n",
		DnsTypeToString(qtype), qname,
		dns.RcodeToString[msg.Rcode],
		len(msg.Answer), len(msg.Ns), len(msg.Extra),
		authInfo)
}