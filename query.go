package recursive

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// Query execution constants
	maxCNAMEChain     = 10
	queryLogThreshold = 100 * time.Millisecond

	// Cache control
	cacheExtraRecords = true // whether to cache additional records
)

// queryContext represents the execution context for a DNS query
type queryContext struct {
	recursive   *Recursive
	cache       Cacher
	logWriter   io.Writer
	startTime   time.Time
	depth       int
	queriesSent int
	stepsTaken  int

	// Query state
	disableMinimization bool
	glueRecords         map[string][]netip.Addr
	cnameChain          map[string]struct{}
}

// newQueryContext creates a new query execution context
func newQueryContext(r *Recursive, cache Cacher, logWriter io.Writer) *queryContext {
	if logWriter == nil {
		logWriter = r.DefaultLogWriter
	}

	return &queryContext{
		recursive:   r,
		cache:       cache,
		logWriter:   logWriter,
		startTime:   time.Now(),
		glueRecords: make(map[string][]netip.Addr),
	}
}

// shouldLog returns true if debug logging is enabled
func (qc *queryContext) shouldLog() bool {
	return qc.logWriter != nil
}

// logMessage writes a debug message with timing and depth information
func (qc *queryContext) logMessage(format string, args ...interface{}) {
	if !qc.shouldLog() {
		return
	}

	elapsed := time.Since(qc.startTime).Milliseconds()
	indent := strings.Repeat("  ", qc.depth)
	fmt.Fprintf(qc.logWriter, "[%5d %2d] %s", elapsed, qc.depth, indent)
	fmt.Fprintf(qc.logWriter, format, args...)
}

// enterDepth increments the recursion depth, returning error if too deep
func (qc *queryContext) enterDepth() error {
	if qc.depth >= maxDepth {
		return ErrMaxDepth
	}
	qc.depth++
	return nil
}

// exitDepth decrements the recursion depth
func (qc *queryContext) exitDepth() {
	qc.depth--
}

// incrementSteps increments the step counter, returning error if too many steps
func (qc *queryContext) incrementSteps() error {
	qc.stepsTaken++
	if qc.stepsTaken > maxSteps {
		return newMaxStepsError(maxSteps, qc.stepsTaken)
	}
	return nil
}

// ResolveWithOptions performs recursive DNS resolution with specified options
func (r *Recursive) ResolveWithOptions(ctx context.Context, cache Cacher, logw io.Writer, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	// Clean up expired data periodically
	r.cleanupServerCookies()

	// Normalize query name
	qname = dns.CanonicalName(qname)

	// Check cache first if available
	if cache != nil {
		if msg := cache.DnsGet(qname, qtype); msg != nil {
			return msg, netip.Addr{}, nil
		}
	}

	// Create query context and execute
	qc := newQueryContext(r, cache, logw)
	msg, serverAddr, err := qc.executeQuery(ctx, qname, qtype)

	// Post-process and cache result
	if msg != nil {
		err = qc.validateAndCacheResult(msg, qname, qtype, cache, err)
	}

	// Log final results if debugging
	if qc.shouldLog() {
		qc.logFinalResult(msg, serverAddr, err)
	}

	return msg, serverAddr, err
}

// executeQuery performs the main query execution logic
func (qc *queryContext) executeQuery(ctx context.Context, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	if err := qc.enterDepth(); err != nil {
		return nil, netip.Addr{}, err
	}
	defer qc.exitDepth()

	// Normalize query name using miekg/dns utilities
	qname = dns.CanonicalName(qname)

	// Start with root servers
	nameservers := qc.getRootNameservers()

	var finalMessage *dns.Msg
	var finalServer netip.Addr

	// Iterate through domain labels (QNAME minimization)
	labelIndex := 0
	isComplete := false

	for !isComplete {
		labelIndex++
		currentLabel, isComplete := qc.getCurrentQueryLabel(qname, qtype, labelIndex)

		qc.logMessage("QUERY%s %s %q from %v\n",
			map[bool]string{true: " FINAL", false: ""}[isComplete],
			DnsTypeToString(currentLabel.qtype), currentLabel.name,
			qc.formatNameserverList(nameservers[:min(4, len(nameservers))]))

		// Query current nameservers
		response, newNameservers, err := qc.queryNameservers(ctx, nameservers, currentLabel)
		if err != nil {
			return nil, netip.Addr{}, err
		}

		if response != nil {
			finalMessage = response.message
			finalServer = response.server

			// Update nameservers if we got new ones
			if len(newNameservers) > 0 {
				nameservers = newNameservers
			}
		}

		// Handle special cases (REFUSED, SERVFAIL, etc.)
		if finalMessage != nil && qc.shouldRetryWithoutMinimization(finalMessage) {
			qc.disableMinimization = true
			qc.logMessage("got REFUSED, retrying without QNAME minimization\n")
			return qc.executeQuery(ctx, qname, qtype)
		}
	}

	// Final query phase - ask for the actual record
	if finalMessage != nil {
		finalResponse, err := qc.performFinalQuery(ctx, nameservers, qname, qtype)
		if err == nil && finalResponse != nil {
			finalMessage = finalResponse.message
			finalServer = finalResponse.server
		}
	}

	// Handle CNAME following using utility function
	if finalMessage != nil && qtype != dns.TypeCNAME {
		if cnameTarget := ExtractCNAMETarget(finalMessage); cnameTarget != "" {
			return qc.followCNAME(ctx, finalMessage, cnameTarget, qtype)
		}
	}

	// Ensure we have a valid response
	if finalMessage == nil {
		finalMessage = CreateErrorResponse(qname, qtype, dns.RcodeServerFailure)
	}

	return finalMessage, finalServer, nil
}

// queryLabel represents a DNS query with name and type
type queryLabel struct {
	name  string
	qtype uint16
}

// getCurrentQueryLabel determines what to query based on QNAME minimization
func (qc *queryContext) getCurrentQueryLabel(qname string, qtype uint16, labelIndex int) (queryLabel, bool) {
	if qc.disableMinimization {
		return queryLabel{qname, qtype}, true
	}

	// Check if we need glue records for this name
	if _, needsGlue := qc.glueRecords[qname]; needsGlue {
		return queryLabel{qname, qtype}, true
	}

	// QNAME minimization: query progressively longer suffixes using miekg/dns utilities
	labelStart, isComplete := dns.PrevLabel(qname, labelIndex)
	currentName := qname[labelStart:]
	currentType := dns.TypeNS

	if isComplete {
		currentType = qtype
	}

	return queryLabel{currentName, currentType}, isComplete
}

// queryResponse represents a response from a nameserver query
type queryResponse struct {
	message *dns.Msg
	server  netip.Addr
}

// queryNameservers attempts to query all provided nameservers
func (qc *queryContext) queryNameservers(ctx context.Context, nameservers []nameserverInfo, label queryLabel) (*queryResponse, []nameserverInfo, error) {
	var lastValidResponse *queryResponse
	var lastRcode int

	for _, ns := range nameservers {
		// Resolve nameserver address if needed
		if err := qc.resolveNameserverAddress(ctx, &ns); err != nil {
			continue
		}

		if !qc.recursive.isAddressUsable(ns.address) {
			continue
		}

		// Perform the actual DNS query
		response, err := qc.performDNSQuery(ctx, ns.address, label.name, label.qtype)
		if err != nil {
			qc.logMessage("FAILED @%v %s %q: %v\n", ns.address, DnsTypeToString(label.qtype), label.name, err)
			continue
		}

		lastRcode = response.Rcode

		switch response.Rcode {
		case dns.RcodeSuccess:
			// Cache authoritative responses
			if response.Authoritative || qc.hasUsableAnswers(response) {
				qc.cacheResponse(response)
			}

			// Extract new nameservers from response
			newNameservers := qc.extractNameservers(response)
			lastValidResponse = &queryResponse{response, ns.address}

			if len(newNameservers) > 0 {
				return lastValidResponse, newNameservers, nil
			}

		case dns.RcodeServerFailure:
			// SERVFAIL - try next server, but cache if it's the final query
			lastValidResponse = &queryResponse{response, ns.address}
			continue

		case dns.RcodeRefused:
			// REFUSED - might need to retry without minimization
			lastValidResponse = &queryResponse{response, ns.address}
			return lastValidResponse, nil, nil

		default:
			// Other error codes (NXDOMAIN, etc.)
			qc.cacheResponse(response)
			lastValidResponse = &queryResponse{response, ns.address}
			return lastValidResponse, nil, nil
		}
	}

	// Handle case where all servers failed
	if lastValidResponse == nil {
		return nil, nil, fmt.Errorf("no nameserver responded successfully (last rcode: %s)", dns.RcodeToString[lastRcode])
	}

	return lastValidResponse, nil, nil
}

// nameserverInfo represents a nameserver with optional address
type nameserverInfo struct {
	hostname string
	address  netip.Addr
}

// formatNameserverList formats nameserver list for logging
func (qc *queryContext) formatNameserverList(nameservers []nameserverInfo) []string {
	result := make([]string, len(nameservers))
	for i, ns := range nameservers {
		if ns.address.IsValid() {
			result[i] = fmt.Sprintf("%s(%s)", ns.hostname, ns.address)
		} else {
			result[i] = ns.hostname
		}
	}
	return result
}

// getRootNameservers returns the current root nameservers
func (qc *queryContext) getRootNameservers() []nameserverInfo {
	roots4, roots6 := qc.recursive.GetRoots()
	nameservers := make([]nameserverInfo, 0, len(roots4)+len(roots6))

	for _, addr := range roots4 {
		nameservers = append(nameservers, nameserverInfo{"root", addr})
	}
	for _, addr := range roots6 {
		nameservers = append(nameservers, nameserverInfo{"root", addr})
	}

	return nameservers
}

// Additional helper methods would continue here...
// This includes: resolveNameserverAddress, performDNSQuery, extractNameservers,
// performFinalQuery, followCNAME, cacheResponse, etc.
