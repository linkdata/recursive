package recursive

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMaxDepthError(t *testing.T) {
	maxDepth := 32
	currentDepth := 35

	err := NewMaxDepthError(maxDepth, currentDepth)

	// Test error message
	expectedMsg := "recursion depth exceeded 32 (current: 35)"
	if err.Error() != expectedMsg {
		t.Errorf("MaxDepthError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var maxDepthErr *MaxDepthError
	if !errors.As(err, &maxDepthErr) {
		t.Error("error should be assignable to *MaxDepthError")
	}

	// Test fields
	if maxDepthErr.MaxDepth != maxDepth {
		t.Errorf("MaxDepthError.MaxDepth = %d; want %d", maxDepthErr.MaxDepth, maxDepth)
	}
	if maxDepthErr.Depth != currentDepth {
		t.Errorf("MaxDepthError.Depth = %d; want %d", maxDepthErr.Depth, currentDepth)
	}

	// Test Is method
	anotherMaxDepthErr := &MaxDepthError{}
	if !errors.Is(err, anotherMaxDepthErr) {
		t.Error("MaxDepthError should match other MaxDepthError with Is()")
	}

	// Test Is method with different error type
	if errors.Is(err, ErrInvalidCookie) {
		t.Error("MaxDepthError should not match different error type")
	}
}

func TestMaxStepsError(t *testing.T) {
	maxSteps := 1000
	currentSteps := 1001

	err := NewMaxStepsError(maxSteps, currentSteps)

	// Test error message
	expectedMsg := "resolve steps exceeded 1000 (current: 1001)"
	if err.Error() != expectedMsg {
		t.Errorf("MaxStepsError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var maxStepsErr *MaxStepsError
	if !errors.As(err, &maxStepsErr) {
		t.Error("error should be assignable to *MaxStepsError")
	}

	// Test fields
	if maxStepsErr.MaxSteps != maxSteps {
		t.Errorf("MaxStepsError.MaxSteps = %d; want %d", maxStepsErr.MaxSteps, maxSteps)
	}
	if maxStepsErr.Steps != currentSteps {
		t.Errorf("MaxStepsError.Steps = %d; want %d", maxStepsErr.Steps, currentSteps)
	}

	// Test Is method
	if !errors.Is(err, &MaxStepsError{}) {
		t.Error("MaxStepsError should match other MaxStepsError with Is()")
	}
}

func TestUnknownQueryTypeError(t *testing.T) {
	queryType := "INVALID"

	err := NewUnknownQueryTypeError(queryType)

	// Test error message
	expectedMsg := "unknown query type: INVALID"
	if err.Error() != expectedMsg {
		t.Errorf("UnknownQueryTypeError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var unknownTypeErr *UnknownQueryTypeError
	if !errors.As(err, &unknownTypeErr) {
		t.Error("error should be assignable to *UnknownQueryTypeError")
	}

	// Test field
	if unknownTypeErr.QueryType != queryType {
		t.Errorf("UnknownQueryTypeError.QueryType = %q; want %q", unknownTypeErr.QueryType, queryType)
	}

	// Test Is method
	if !errors.Is(err, &UnknownQueryTypeError{}) {
		t.Error("UnknownQueryTypeError should match other UnknownQueryTypeError with Is()")
	}
}

func TestUnsupportedQueryClassError(t *testing.T) {
	queryClass := uint16(255)

	err := NewUnsupportedQueryClassError(queryClass)

	// Test error message
	expectedMsg := "unsupported query class: 255"
	if err.Error() != expectedMsg {
		t.Errorf("UnsupportedQueryClassError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var unsupportedClassErr *UnsupportedQueryClassError
	if !errors.As(err, &unsupportedClassErr) {
		t.Error("error should be assignable to *UnsupportedQueryClassError")
	}

	// Test field
	if unsupportedClassErr.QueryClass != queryClass {
		t.Errorf("UnsupportedQueryClassError.QueryClass = %d; want %d", unsupportedClassErr.QueryClass, queryClass)
	}

	// Test Is method
	if !errors.Is(err, &UnsupportedQueryClassError{}) {
		t.Error("UnsupportedQueryClassError should match other UnsupportedQueryClassError with Is()")
	}
}

func TestInvalidFQDNError(t *testing.T) {
	name := "invalid-name"

	err := NewInvalidFQDNError(name)

	// Test error message
	expectedMsg := "query name is not FQDN: invalid-name"
	if err.Error() != expectedMsg {
		t.Errorf("InvalidFQDNError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var invalidFQDNErr *InvalidFQDNError
	if !errors.As(err, &invalidFQDNErr) {
		t.Error("error should be assignable to *InvalidFQDNError")
	}

	// Test field
	if invalidFQDNErr.Name != name {
		t.Errorf("InvalidFQDNError.Name = %q; want %q", invalidFQDNErr.Name, name)
	}

	// Test Is method
	if !errors.Is(err, &InvalidFQDNError{}) {
		t.Error("InvalidFQDNError should match other InvalidFQDNError with Is()")
	}
}

func TestNetworkError(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	protocol := "udp"
	operation := "dial"
	innerErr := errors.New("connection refused")

	err := NewNetworkError(addr, protocol, operation, innerErr)

	// Test error message
	expectedMsg := "dial udp to 192.0.2.1: connection refused"
	if err.Error() != expectedMsg {
		t.Errorf("NetworkError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Error("error should be assignable to *NetworkError")
	}

	// Test fields
	if netErr.Addr != addr {
		t.Errorf("NetworkError.Addr = %v; want %v", netErr.Addr, addr)
	}
	if netErr.Protocol != protocol {
		t.Errorf("NetworkError.Protocol = %q; want %q", netErr.Protocol, protocol)
	}
	if netErr.Operation != operation {
		t.Errorf("NetworkError.Operation = %q; want %q", netErr.Operation, operation)
	}

	// Test Unwrap
	if !errors.Is(err, innerErr) {
		t.Error("NetworkError should unwrap to inner error")
	}

	// Test IsExpired
	if netErr.IsExpired(time.Hour) {
		t.Error("NetworkError should not be expired with 1 hour TTL")
	}
	if !netErr.IsExpired(0) {
		t.Error("NetworkError should be expired with 0 TTL")
	}

	// Test Is method
	if !errors.Is(err, &NetworkError{}) {
		t.Error("NetworkError should match other NetworkError with Is()")
	}
}

func TestQueryError(t *testing.T) {
	qname := "example.org."
	qtype := dns.TypeA
	server := netip.MustParseAddr("8.8.8.8")
	operation := "exchange"
	innerErr := errors.New("timeout")

	err := NewQueryError(qname, qtype, server, operation, innerErr)

	// Test error message
	expectedMsg := "exchange query for A example.org. to 8.8.8.8: timeout"
	if err.Error() != expectedMsg {
		t.Errorf("QueryError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var queryErr *QueryError
	if !errors.As(err, &queryErr) {
		t.Error("error should be assignable to *QueryError")
	}

	// Test fields
	if queryErr.QName != qname {
		t.Errorf("QueryError.QName = %q; want %q", queryErr.QName, qname)
	}
	if queryErr.QType != qtype {
		t.Errorf("QueryError.QType = %d; want %d", queryErr.QType, qtype)
	}
	if queryErr.Server != server {
		t.Errorf("QueryError.Server = %v; want %v", queryErr.Server, server)
	}
	if queryErr.Operation != operation {
		t.Errorf("QueryError.Operation = %q; want %q", queryErr.Operation, operation)
	}

	// Test Unwrap
	if !errors.Is(err, innerErr) {
		t.Error("QueryError should unwrap to inner error")
	}

	// Test Is method
	if !errors.Is(err, &QueryError{}) {
		t.Error("QueryError should match other QueryError with Is()")
	}
}

func TestCacheError(t *testing.T) {
	operation := "get"
	key := "example.org./A"
	innerErr := errors.New("cache miss")

	err := NewCacheError(operation, key, innerErr)

	// Test error message
	expectedMsg := "cache get for example.org./A: cache miss"
	if err.Error() != expectedMsg {
		t.Errorf("CacheError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var cacheErr *CacheError
	if !errors.As(err, &cacheErr) {
		t.Error("error should be assignable to *CacheError")
	}

	// Test fields
	if cacheErr.Operation != operation {
		t.Errorf("CacheError.Operation = %q; want %q", cacheErr.Operation, operation)
	}
	if cacheErr.Key != key {
		t.Errorf("CacheError.Key = %q; want %q", cacheErr.Key, key)
	}

	// Test Unwrap
	if !errors.Is(err, innerErr) {
		t.Error("CacheError should unwrap to inner error")
	}

	// Test Is method
	if !errors.Is(err, &CacheError{}) {
		t.Error("CacheError should match other CacheError with Is()")
	}
}

func TestConfigurationError(t *testing.T) {
	component := "resolver"
	reason := "invalid timeout value"

	err := NewConfigurationError(component, reason)

	// Test error message
	expectedMsg := "configuration error in resolver: invalid timeout value"
	if err.Error() != expectedMsg {
		t.Errorf("ConfigurationError.Error() = %q; want %q", err.Error(), expectedMsg)
	}

	// Test type assertion
	var configErr *ConfigurationError
	if !errors.As(err, &configErr) {
		t.Error("error should be assignable to *ConfigurationError")
	}

	// Test fields
	if configErr.Component != component {
		t.Errorf("ConfigurationError.Component = %q; want %q", configErr.Component, component)
	}
	if configErr.Reason != reason {
		t.Errorf("ConfigurationError.Reason = %q; want %q", configErr.Reason, reason)
	}

	// Test Is method
	if !errors.Is(err, &ConfigurationError{}) {
		t.Error("ConfigurationError should match other ConfigurationError with Is()")
	}
}

// Test error chaining and wrapping
func TestErrorChaining(t *testing.T) {
	// Create a chain of errors
	rootErr := errors.New("root cause")
	netErr := NewNetworkError(netip.MustParseAddr("192.0.2.1"), "tcp", "connect", rootErr)
	queryErr := NewQueryError("example.org.", dns.TypeA, netip.MustParseAddr("8.8.8.8"), "resolve", netErr)

	// Test that we can unwrap through the chain
	if !errors.Is(queryErr, rootErr) {
		t.Error("should be able to unwrap through error chain to root cause")
	}

	// Test that we can check for intermediate types
	if !errors.Is(queryErr, &NetworkError{}) {
		t.Error("should be able to check for NetworkError in chain")
	}

	// Test As with intermediate types
	var intermediateNetErr *NetworkError
	if !errors.As(queryErr, &intermediateNetErr) {
		t.Error("should be able to extract NetworkError from chain")
	}
	if intermediateNetErr.Protocol != "tcp" {
		t.Errorf("extracted NetworkError has wrong protocol: got %q, want %q", intermediateNetErr.Protocol, "tcp")
	}
}

// Test error comparison and identification
func TestErrorComparison(t *testing.T) {
	// Test that static errors can be compared
	err1 := ErrInvalidCookie
	err2 := ErrInvalidCookie

	if !errors.Is(err1, err2) {
		t.Error("same static errors should be equal")
	}

	// Test that different static errors are different
	if errors.Is(ErrInvalidCookie, ErrNoResponse) {
		t.Error("different static errors should not be equal")
	}

	// Test that custom errors of same type but different values are equal with Is()
	maxDepthErr1 := NewMaxDepthError(32, 35)
	maxDepthErr2 := NewMaxDepthError(16, 20)

	if !errors.Is(maxDepthErr1, &MaxDepthError{}) {
		t.Error("MaxDepthError should match type check")
	}
	if !errors.Is(maxDepthErr2, &MaxDepthError{}) {
		t.Error("MaxDepthError should match type check regardless of values")
	}
}

// Benchmark error creation
func BenchmarkErrorCreation(b *testing.B) {
	addr := netip.MustParseAddr("192.0.2.1")

	b.Run("StaticError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ErrInvalidCookie
		}
	})

	b.Run("CustomError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewNetworkError(addr, "udp", "dial", errors.New("test"))
		}
	})

	b.Run("MaxDepthError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewMaxDepthError(32, 35)
		}
	})
}

// Test error string formatting
func TestErrorStringFormatting(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains []string
	}{
		{
			name:     "MaxDepthError",
			err:      newMaxDepthError(32, 35),
			contains: []string{"recursion depth", "exceeded", "32", "35"},
		},
		{
			name:     "NetworkError",
			err:      NewNetworkError(netip.MustParseAddr("192.0.2.1"), "udp", "dial", errors.New("refused")),
			contains: []string{"dial", "udp", "192.0.2.1", "refused"},
		},
		{
			name:     "QueryError",
			err:      NewQueryError("test.example.", dns.TypeAAAA, netip.MustParseAddr("::1"), "exchange", errors.New("timeout")),
			contains: []string{"exchange", "AAAA", "test.example.", "::1", "timeout"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, contain := range tt.contains {
				if !strings.Contains(errStr, contain) {
					t.Errorf("error string %q should contain %q", errStr, contain)
				}
			}
		})
	}
}
