package recursive

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	networkErrorTTL    = time.Minute // How long to remember network errors
	maxNetworkErrors   = 1000        // Maximum number of errors to track per protocol
	errorCleanupPeriod = 5 * time.Minute
)

// networkErrorManager handles tracking and managing network errors
type networkErrorManager struct {
	mu       sync.RWMutex
	udpErrs  map[netip.Addr]*NetworkError
	tcpErrs  map[netip.Addr]*NetworkError
	lastCleanup time.Time
}

// newNetworkErrorManager creates a new network error manager
func newNetworkErrorManager() *networkErrorManager {
	return &networkErrorManager{
		udpErrs: make(map[netip.Addr]*NetworkError),
		tcpErrs: make(map[netip.Addr]*NetworkError),
	}
}

// recordError records a network error for the given address and protocol
func (nem *networkErrorManager) recordError(protocol string, addr netip.Addr, operation string, err error) (isIPv6, isUDP bool) {
	if err == nil || !addr.IsValid() {
		return false, false
	}
	
	isIPv6 = addr.Is6()
	isUDP = strings.HasPrefix(protocol, "udp")
	
	// Only record certain types of errors
	if !nem.shouldRecordError(err) {
		return isIPv6, isUDP
	}
	
	netErr := NewNetworkError(addr, protocol, operation, err).(*NetworkError)
	
	nem.mu.Lock()
	defer nem.mu.Unlock()
	
	// Store in appropriate error map
	errorMap := nem.tcpErrs
	if isUDP {
		errorMap = nem.udpErrs
	}
	
	errorMap[addr] = netErr
	
	// Cleanup if needed
	if time.Since(nem.lastCleanup) > errorCleanupPeriod {
		nem.cleanupExpiredErrorsLocked()
		nem.lastCleanup = time.Now()
	}
	
	return isIPv6, isUDP
}rs
	}
	
	errorMap[addr] = netErr
	
	// Cleanup if needed
	if time.Since(nem.lastCleanup) > errorCleanupPeriod {
		nem.cleanupExpiredErrorsLocked()
		nem.lastCleanup = time.Now()
	}
	
	return isIPv6, isUDP
}

// shouldRecordError determines if an error should be tracked
func (nem *networkErrorManager) shouldRecordError(err error) bool {
	// Always record these error types
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	
	// Check for network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	
	// Check error message for common patterns
	errStr := strings.ToLower(err.Error())
	networkErrorPatterns := []string{
		"timeout",
		"refused", 
		"unreachable",
		"no route",
		"connection reset",
		"network not implemented",
	}
	
	for _, pattern := range networkErrorPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	
	return false
}

// isAddressUsable checks if an address is usable for the given protocol
func (nem *networkErrorManager) isAddressUsable(protocol string, addr netip.Addr) error {
	if !addr.IsValid() {
		return ErrInvalidAddress
	}
	
	nem.mu.RLock()
	defer nem.mu.RUnlock()
	
	// Check appropriate error map
	var errorMap map[netip.Addr]*NetworkError
	if strings.HasPrefix(protocol, "udp") {
		errorMap = nem.udpErrs
	} else {
		errorMap = nem.tcpErrs
	}
	
	if netErr, exists := errorMap[addr]; exists {
		// Check if error has expired
		if netErr.IsExpired(networkErrorTTL) {
			// Error has expired, remove it
			nem.mu.RUnlock()
			nem.mu.Lock()
			// Double-check it's still there and expired
			if netErr, stillExists := errorMap[addr]; stillExists && netErr.IsExpired(networkErrorTTL) {
				delete(errorMap, addr)
			}
			nem.mu.Unlock()
			nem.mu.RLock()
			return nil // Address is now usable
		}
		return netErr // Address still has recent error
	}
	
	return nil // No error recorded
}

// cleanupExpiredErrorsLocked removes expired errors (must be called with write lock)
func (nem *networkErrorManager) cleanupExpiredErrorsLocked() {
	now := time.Now()
	
	nem.cleanupErrorMap(nem.udpErrs, now)
	nem.cleanupErrorMap(nem.tcpErrs, now)
}

// cleanupErrorMap removes expired errors from the given map
func (nem *networkErrorManager) cleanupErrorMap(errorMap map[netip.Addr]*NetworkError, now time.Time) {
	expiredAddrs := make([]netip.Addr, 0)
	
	for addr, netErr := range errorMap {
		if now.Sub(netErr.Timestamp) > networkErrorTTL {
			expiredAddrs = append(expiredAddrs, addr)
		}
	}
	
	for _, addr := range expiredAddrs {
		delete(errorMap, addr)
	}
	
	// If we have too many errors, remove the oldest ones
	if len(errorMap) > maxNetworkErrors {
		nem.pruneOldestErrors(errorMap)
	}
}

// pruneOldestErrors removes the oldest errors when the map is too large
func (nem *networkErrorManager) pruneOldestErrors(errorMap map[netip.Addr]*NetworkError) {
	// Create slice for sorting by timestamp
	type errorEntry struct {
		addr netip.Addr
		timestamp time.Time
	}
	
	entries := make([]errorEntry, 0, len(errorMap))
	for addr, netErr := range errorMap {
		entries = append(entries, errorEntry{
			addr:      addr,
			timestamp: netErr.Timestamp,
		})
	}
	
	// Simple sort by timestamp (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].timestamp.After(entries[j].timestamp) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	
	// Remove excess entries (keep the newest ones)
	entriesToRemove := len(entries) - maxNetworkErrors/2 // Remove half when pruning
	for i := 0; i < entriesToRemove && i < len(entries); i++ {
		delete(errorMap, entries[i].addr)
	}
}

// getStats returns network error statistics
func (nem *networkErrorManager) getStats() (udpErrors, tcpErrors int) {
	nem.mu.RLock()
	defer nem.mu.RUnlock()
	
	return len(nem.udpErrs), len(nem.tcpErrs)
}

// clearErrors removes all recorded errors
func (nem *networkErrorManager) clearErrors() {
	nem.mu.Lock()
	defer nem.mu.Unlock()
	
	nem.udpErrs = make(map[netip.Addr]*NetworkError)
	nem.tcpErrs = make(map[netip.Addr]*NetworkError)
}