package recursive

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Core error types for better error handling and context
var (
	// ErrInvalidCookie is returned if the DNS cookie from the server is invalid.
	ErrInvalidCookie = errors.New("invalid DNS cookie")

	// ErrNoResponse is returned when no authoritative server could be successfully queried.
	ErrNoResponse = errors.New("no authoritative response available")

	// ErrQuestionMismatch is returned when the DNS response is not for what was queried.
	ErrQuestionMismatch = errors.New("DNS response question mismatch")

	// ErrNoUsableServers is returned when no servers are available for querying.
	ErrNoUsableServers = errors.New("no usable DNS servers available")

	// ErrNetworkDisabled is returned when a network protocol is disabled.
	ErrNetworkDisabled = errors.New("network protocol disabled")

	// ErrInvalidQueryString is returned when a query string cannot be parsed.
	ErrInvalidQueryString = errors.New("invalid query string")

	// ErrInvalidAddress is returned when an address is invalid.
	ErrInvalidAddress = errors.New("invalid address")

	// ErrNilMessage is returned when a message is nil.
	ErrNilMessage = errors.New("message is nil")

	// ErrNoQuestions is returned when a message has no questions.
	ErrNoQuestions = errors.New("message has no questions")

	// ErrMultipleQuestions is returned when a message has multiple questions.
	ErrMultipleQuestions = errors.New("message has multiple questions")
)

// maxDepthError represents an error when recursion depth is exceeded
type maxDepthError struct {
	MaxDepth int
	Depth    int
}

func (e *maxDepthError) Error() string {
	return fmt.Sprintf("recursion depth exceeded %d (current: %d)", e.MaxDepth, e.Depth)
}

func (e *maxDepthError) Is(target error) bool {
	_, ok := target.(*maxDepthError)
	return ok
}

// maxStepsError represents an error when query steps are exceeded
type maxStepsError struct {
	MaxSteps int
	Steps    int
}

func (e *maxStepsError) Error() string {
	return fmt.Sprintf("resolve steps exceeded %d (current: %d)", e.MaxSteps, e.Steps)
}

func (e *maxStepsError) Is(target error) bool {
	_, ok := target.(*maxStepsError)
	return ok
}

// unknownQueryTypeError represents an error for unknown DNS query types
type unknownQueryTypeError struct {
	QueryType string
}

func (e *unknownQueryTypeError) Error() string {
	return fmt.Sprintf("unknown query type: %s", e.QueryType)
}

func (e *unknownQueryTypeError) Is(target error) bool {
	_, ok := target.(*unknownQueryTypeError)
	return ok
}

// unsupportedQueryClassError represents an error for unsupported query classes
type unsupportedQueryClassError struct {
	QueryClass uint16
}

func (e *unsupportedQueryClassError) Error() string {
	return fmt.Sprintf("unsupported query class: %d", e.QueryClass)
}

func (e *unsupportedQueryClassError) Is(target error) bool {
	_, ok := target.(*unsupportedQueryClassError)
	return ok
}

// invalidFQDNError represents an error when a name is not a valid FQDN
type invalidFQDNError struct {
	Name string
}

func (e *invalidFQDNError) Error() string {
	return fmt.Sprintf("query name is not FQDN: %s", e.Name)
}

func (e *invalidFQDNError) Is(target error) bool {
	_, ok := target.(*invalidFQDNError)
	return ok
}

// NetworkError represents a network-related error with timing information
type NetworkError struct {
	Addr      netip.Addr
	Protocol  string
	Operation string
	Err       error
	Timestamp time.Time
}

func (ne *NetworkError) Error() string {
	return fmt.Sprintf("%s %s to %s: %v", ne.Operation, ne.Protocol, ne.Addr, ne.Err)
}

func (ne *NetworkError) Unwrap() error {
	return ne.Err
}

func (ne *NetworkError) Is(target error) bool {
	_, ok := target.(*NetworkError)
	return ok
}

func (ne *NetworkError) IsExpired(ttl time.Duration) bool {
	return time.Since(ne.Timestamp) > ttl
}

// QueryError represents an error that occurred during DNS query processing
type QueryError struct {
	QName     string
	QType     uint16
	Server    netip.Addr
	Operation string
	Err       error
}

func (qe *QueryError) Error() string {
	return fmt.Sprintf("%s query for %s %s to %s: %v",
		qe.Operation, DnsTypeToString(qe.QType), qe.QName, qe.Server, qe.Err)
}

func (qe *QueryError) Unwrap() error {
	return qe.Err
}

func (qe *QueryError) Is(target error) bool {
	_, ok := target.(*QueryError)
	return ok
}

// CacheError represents cache-related errors
type CacheError struct {
	Operation string
	Key       string
	Err       error
}

func (ce *CacheError) Error() string {
	return fmt.Sprintf("cache %s for %s: %v", ce.Operation, ce.Key, ce.Err)
}

func (ce *CacheError) Unwrap() error {
	return ce.Err
}

func (ce *CacheError) Is(target error) bool {
	_, ok := target.(*CacheError)
	return ok
}

// ConfigurationError represents configuration-related errors
type ConfigurationError struct {
	Component string
	Reason    string
}

func (ce *ConfigurationError) Error() string {
	return fmt.Sprintf("configuration error in %s: %s", ce.Component, ce.Reason)
}

func (ce *ConfigurationError) Is(target error) bool {
	_, ok := target.(*ConfigurationError)
	return ok
}

// Helper functions to create specific errors

// newMaxDepthError creates a new maxDepthError
func newMaxDepthError(maxDepth, currentDepth int) error {
	return &maxDepthError{MaxDepth: maxDepth, Depth: currentDepth}
}

// newMaxStepsError creates a new maxStepsError
func newMaxStepsError(maxSteps, currentSteps int) error {
	return &maxStepsError{MaxSteps: maxSteps, Steps: currentSteps}
}

// newUnknownQueryTypeError creates a new unknownQueryTypeError
func newUnknownQueryTypeError(queryType string) error {
	return &unknownQueryTypeError{QueryType: queryType}
}

// newUnsupportedQueryClassError creates a new unsupportedQueryClassError
func newUnsupportedQueryClassError(queryClass uint16) error {
	return &unsupportedQueryClassError{QueryClass: queryClass}
}

// newInvalidFQDNError creates a new invalidFQDNError
func newInvalidFQDNError(name string) error {
	return &invalidFQDNError{Name: name}
}

// NewNetworkError creates a new NetworkError
func NewNetworkError(addr netip.Addr, protocol, operation string, err error) error {
	return &NetworkError{
		Addr:      addr,
		Protocol:  protocol,
		Operation: operation,
		Err:       err,
		Timestamp: time.Now(),
	}
}

// NewQueryError creates a new QueryError
func NewQueryError(qname string, qtype uint16, server netip.Addr, operation string, err error) error {
	return &QueryError{
		QName:     qname,
		QType:     qtype,
		Server:    server,
		Operation: operation,
		Err:       err,
	}
}

// NewCacheError creates a new CacheError
func NewCacheError(operation, key string, err error) error {
	return &CacheError{
		Operation: operation,
		Key:       key,
		Err:       err,
	}
}

// NewConfigurationError creates a new ConfigurationError
func NewConfigurationError(component, reason string) error {
	return &ConfigurationError{
		Component: component,
		Reason:    reason,
	}
}
