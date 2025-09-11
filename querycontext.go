package recursive

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Additional query helper methods using miekg/dns utilities

// shouldRetryWithoutMinimization determines if we should retry without QNAME minimization
func (qc *queryContext) shouldRetryWithoutMinimization(msg *dns.Msg) bool {
	return msg != nil && msg.Rcode == dns.RcodeRefused && !qc.disableMinimization
}

// hasUsableAnswers checks if a response has usable answer records
func (qc *queryContext) hasUsableAnswers(msg *dns.Msg) bool {
	return HasAnswerRecords(msg) || (msg.Authoritative && msg.Rcode != dns.RcodeSuccess)
}

// cacheResponse caches a DNS response if it should be cached
func (qc *queryContext) cacheResponse(msg *dns.Msg) {
	if qc.cache != nil && ShouldCacheResponse(msg) {
		qc.cache.DnsSet(msg)
	}
}

// extractNameservers extracts nameserver information from a DNS response
func (qc *queryContext) extractNameservers(msg *dns.Msg) []nameserverInfo {
	nameserverList, glueMap := ExtractNameservers(msg)

	var result []nameserverInfo

	// Process each nameserver
	for _, nsName := range nameserverList {
		canonicalName := NormalizeQueryName(nsName)

		// Add to glue records map for future resolution
		qc.addToGlueMap(canonicalName)

		// Check if we have glue records for this nameserver
		if addrs, hasGlue := glueMap[canonicalName]; hasGlue {
			// Add each address as a separate nameserver entry
			for _, addr := range addrs {
				if qc.recursive.isAddressUsable(addr) {
					qc.updateGlueRecord(canonicalName, addr)
					result = append(result, nameserverInfo{
						hostname: canonicalName,
						address:  addr,
					})
				}
			}
		} else {
			// No glue - will need to resolve later
			result = append(result, nameserverInfo{
				hostname: canonicalName,
				address:  netip.Addr{}, // Invalid address indicates needs resolution
			})
		}
	}

	// Sort nameservers for consistent ordering using miekg/dns comparison
	slices.SortFunc(result, func(a, b nameserverInfo) int {
		// Nameservers with addresses first
		if a.address.IsValid() && !b.address.IsValid() {
			return -1
		}
		if !a.address.IsValid() && b.address.IsValid() {
			return 1
		}

		// If both have addresses, sort by address
		if a.address.IsValid() && b.address.IsValid() {
			return a.address.Compare(b.address)
		}

		// If neither has address, sort by hostname length then name
		aLabels := GetLabelCount(a.hostname)
		bLabels := GetLabelCount(b.hostname)
		if aLabels != bLabels {
			return aLabels - bLabels
		}

		return strings.Compare(a.hostname, b.hostname)
	})

	return result
}

// addToGlueMap adds a hostname to the glue records map
func (qc *queryContext) addToGlueMap(hostname string) {
	if _, exists := qc.glueRecords[hostname]; !exists {
		qc.glueRecords[hostname] = nil
	}
}

// updateGlueRecord adds an address to the glue records for a hostname
func (qc *queryContext) updateGlueRecord(hostname string, addr netip.Addr) {
	if qc.recursive.isAddressUsable(addr) {
		if addrs, exists := qc.glueRecords[hostname]; exists {
			// Check if address is already present
			for _, existing := range addrs {
				if existing.Compare(addr) == 0 {
					return // Already have this address
				}
			}
			qc.glueRecords[hostname] = append(addrs, addr)
		}
	}
}

// resolveNameserverAddress resolves the address of a nameserver if needed
func (qc *queryContext) resolveNameserverAddress(ctx context.Context, ns *nameserverInfo) error {
	if ns.address.IsValid() {
		return nil // Already has address
	}

	// Check if we already marked this for glue resolution
	if _, needsGlue := qc.glueRecords[ns.hostname]; needsGlue {
		qc.logMessage("GLUE lookup for NS %q\n", ns.hostname)

		// Try to resolve both A and AAAA records
		for _, qtype := range qc.getGlueQueryTypes() {
			response, _, err := qc.executeQuery(ctx, ns.hostname, qtype)
			if err == nil && IsSuccessfulResponse(response) {
				// Extract addresses from the response
				addresses := ExtractAddressRecords(response)
				if addrs, found := addresses[ns.hostname]; found {
					for _, addr := range addrs {
						if qc.recursive.isAddressUsable(addr) {
							ns.address = addr // Use first usable address
							qc.updateGlueRecord(ns.hostname, addr)
							return nil
						}
					}
				}
			}
		}

		return fmt.Errorf("failed to resolve nameserver %s", ns.hostname)
	}

	return fmt.Errorf("nameserver %s has no address", ns.hostname)
}

// getGlueQueryTypes returns the query types to use for glue record resolution
func (qc *queryContext) getGlueQueryTypes() []uint16 {
	var types []uint16

	qc.recursive.mu.RLock()
	useIPv4 := qc.recursive.config.useIPv4
	useIPv6 := qc.recursive.config.useIPv6
	qc.recursive.mu.RUnlock()

	if useIPv4 {
		types = append(types, dns.TypeA)
	}
	if useIPv6 {
		types = append(types, dns.TypeAAAA)
	}

	return types
}

// performFinalQuery performs the final query for the requested record
func (qc *queryContext) performFinalQuery(ctx context.Context, nameservers []nameserverInfo, qname string, qtype uint16) (*queryResponse, error) {
	// Collect all usable addresses from nameservers
	var addresses []netip.Addr

	for _, ns := range nameservers {
		if ns.address.IsValid() {
			addresses = append(addresses, ns.address)
		} else {
			// Use glue records if available
			if glueAddrs, hasGlue := qc.glueRecords[ns.hostname]; hasGlue {
				addresses = append(addresses, glueAddrs...)
			}
		}
	}

	// Remove duplicates and sort
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	addresses = slices.Compact(addresses)

	if qc.shouldLog() {
		qc.logMessage("final nameservers: %v\n", addresses)
		qc.logGlueRecords()
	}

	// Try each address
	for _, addr := range addresses {
		response, err := qc.performDNSQuery(ctx, addr, qname, qtype)
		if err == nil && !IsTemporaryError(response) {
			qc.cacheResponse(response)
			return &queryResponse{response, addr}, nil
		}

		if qc.shouldLog() {
			qc.logMessage("FAILED @%v %s %q: %v\n", addr, DnsTypeToString(qtype), qname, err)
		}
	}

	return nil, fmt.Errorf("all final nameservers failed")
}

// followCNAME follows a CNAME chain to resolve the final answer
func (qc *queryContext) followCNAME(ctx context.Context, cnameMsg *dns.Msg, target string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	if qc.cnameChain == nil {
		qc.cnameChain = make(map[string]struct{})
	}

	// Check for CNAME loops using normalized names
	normalizedTarget := dns.CanonicalName(target)
	if _, inChain := qc.cnameChain[normalizedTarget]; inChain {
		qc.logMessage("CNAME loop detected for %q\n", target)
		return cnameMsg, netip.Addr{}, nil // Return original response
	}

	// Check chain length
	if len(qc.cnameChain) >= maxCNAMEChain {
		qc.logMessage("CNAME chain too long (>%d)\n", maxCNAMEChain)
		return cnameMsg, netip.Addr{}, nil // Return original response
	}

	// Add to chain
	qc.cnameChain[normalizedTarget] = struct{}{}

	qc.logMessage("CNAME QUERY %q => %q\n", cnameMsg.Question[0].Name, target)

	// Follow the CNAME
	targetMsg, serverAddr, err := qc.executeQuery(ctx, target, qtype)
	if err != nil {
		qc.logMessage("CNAME ERROR %q: %v\n", target, err)
		return cnameMsg, netip.Addr{}, err
	}

	qc.logMessage("CNAME ANSWER %s %q with %d records\n",
		GetResponseCode(targetMsg), target, len(targetMsg.Answer))

	// Merge responses using miekg/dns copy functionality
	mergedMsg := CopyMessage(cnameMsg)
	mergedMsg.Zero = true // Mark as processed

	// Add target answers to the merged response
	mergedMsg.Answer = append(mergedMsg.Answer, targetMsg.Answer...)
	mergedMsg.Rcode = targetMsg.Rcode

	return mergedMsg, serverAddr, nil
}

// logGlueRecords logs current glue records for debugging
func (qc *queryContext) logGlueRecords() {
	if !qc.shouldLog() || qc.depth != 1 {
		return // Only log at top level
	}

	// Get sorted list of glue record names
	glueNames := make([]string, 0, len(qc.glueRecords))
	for name := range qc.glueRecords {
		glueNames = append(glueNames, name)
	}
	slices.Sort(glueNames)

	for _, name := range glueNames {
		addrs := qc.glueRecords[name]
		qc.logMessage("glue: %q: %v\n", name, addrs)
	}
}

// validateAndCacheResult validates and caches the final query result
func (qc *queryContext) validateAndCacheResult(msg *dns.Msg, qname string, qtype uint16, cache Cacher, err error) error {
	if msg == nil {
		return err
	}

	// Validate response matches query for successful responses
	if IsSuccessfulResponse(msg) {
		if err := qc.validateResponseMatch(msg, qname, qtype); err != nil {
			return err
		}
	} else {
		// For error responses, ensure question matches original query
		if !msg.Zero { // Don't modify cached responses
			msg.SetQuestion(dns.Fqdn(qname), qtype)
		}
	}

	// Cache the result if no errors
	if err == nil && cache != nil {
		cache.DnsSet(msg)
	}

	return err
}

// validateResponseMatch ensures the response matches the original query
func (qc *queryContext) validateResponseMatch(msg *dns.Msg, expectedName string, expectedType uint16) error {
	if len(msg.Question) == 0 {
		return ErrNoQuestions
	}

	question := msg.Question[0]
	if !CompareNames(question.Name, expectedName) || question.Qtype != expectedType {
		qc.logMessage("ERROR: ANSWER was for %s %q, not %s %q\n",
			DnsTypeToString(question.Qtype), question.Name,
			DnsTypeToString(expectedType), expectedName)
		return ErrQuestionMismatch
	}

	return nil
}

// logFinalResult logs the final query result
func (qc *queryContext) logFinalResult(msg *dns.Msg, serverAddr netip.Addr, err error) {
	if !qc.shouldLog() {
		return
	}

	if msg != nil {
		fmt.Fprintf(qc.logWriter, "\n%v", msg)
	}

	if qc.queriesSent > 0 {
		fmt.Fprintf(qc.logWriter, "\n;; Sent %d queries in %s",
			qc.queriesSent, FormatDuration(time.Since(qc.startTime)))
	}

	if serverAddr.IsValid() {
		fmt.Fprintf(qc.logWriter, "\n;; SERVER: %v", serverAddr)
	}

	if err != nil {
		fmt.Fprintf(qc.logWriter, "\n;; ERROR: %v", err)
	}

	fmt.Fprintln(qc.logWriter)
}
