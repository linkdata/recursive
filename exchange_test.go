package recursive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockDialer implements proxy.ContextDialer for testing
type mockDialer struct {
	connections map[string]*mockConnection
	dialErrors  map[string]error
}

func newMockDialer() *mockDialer {
	return &mockDialer{
		connections: make(map[string]*mockConnection),
		dialErrors:  make(map[string]error),
	}
}

func (md *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err, exists := md.dialErrors[address]; exists {
		return nil, err
	}

	conn, exists := md.connections[address]
	if !exists {
		conn = newMockConnection()
		md.connections[address] = conn
	}

	return conn, nil
}

// mockConnection implements net.Conn for testing
type mockConnection struct {
	readData  []byte
	writeData []byte
	closed    bool
}

func newMockConnection() *mockConnection {
	return &mockConnection{}
}

func (mc *mockConnection) Read(b []byte) (n int, err error) {
	if mc.closed {
		return 0, io.EOF
	}
	if len(mc.readData) == 0 {
		return 0, io.EOF
	}

	n = copy(b, mc.readData)
	mc.readData = mc.readData[n:]
	return n, nil
}

func (mc *mockConnection) Write(b []byte) (n int, err error) {
	if mc.closed {
		return 0, errors.New("connection closed")
	}
	mc.writeData = append(mc.writeData, b...)
	return len(b), nil
}

func (mc *mockConnection) Close() error {
	mc.closed = true
	return nil
}

func (mc *mockConnection) LocalAddr() net.Addr                { return mockAddr("local") }
func (mc *mockConnection) RemoteAddr() net.Addr               { return mockAddr("remote") }
func (mc *mockConnection) SetDeadline(t time.Time) error      { return nil }
func (mc *mockConnection) SetReadDeadline(t time.Time) error  { return nil }
func (mc *mockConnection) SetWriteDeadline(t time.Time) error { return nil }

type mockAddr string

func (ma mockAddr) Network() string { return "mock" }
func (ma mockAddr) String() string  { return string(ma) }

// Test exchange manager creation
func TestExchangeManagerCreation(t *testing.T) {
	r := &Recursive{}
	qc := &queryContext{}

	em := newExchangeManager(r, qc)

	if em.recursive != r {
		t.Error("exchange manager should reference recursive resolver")
	}
	if em.context != qc {
		t.Error("exchange manager should reference query context")
	}
}

// Test network string generation
func TestGetNetworkString(t *testing.T) {
	em := &exchangeManager{}

	ipv4Addr := netip.MustParseAddr("192.0.2.1")
	ipv6Addr := netip.MustParseAddr("2001:db8::1")

	// Test IPv4
	network := em.getNetworkString("udp", ipv4Addr)
	if network != "udp4" {
		t.Errorf("IPv4 UDP should be udp4, got %s", network)
	}

	network = em.getNetworkString("tcp", ipv4Addr)
	if network != "tcp4" {
		t.Errorf("IPv4 TCP should be tcp4, got %s", network)
	}

	// Test IPv6
	network = em.getNetworkString("udp", ipv6Addr)
	if network != "udp6" {
		t.Errorf("IPv6 UDP should be udp6, got %s", network)
	}

	network = em.getNetworkString("tcp", ipv6Addr)
	if network != "tcp6" {
		t.Errorf("IPv6 TCP should be tcp6, got %s", network)
	}
}

// Test DNS message preparation
func TestPrepareDNSMessage(t *testing.T) {
	r := &Recursive{
		mu:           sync.RWMutex{},
		clientCookie: "test1234",
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	qname := "example.org."
	qtype := dns.TypeA
	serverAddr := netip.MustParseAddr("8.8.8.8")

	// Test without cookies
	msg := em.prepareDNSMessage(qname, qtype, false, serverAddr)

	if len(msg.Question) != 1 {
		t.Error("message should have one question")
	}
	if msg.Question[0].Name != qname {
		t.Errorf("question name should be %s, got %s", qname, msg.Question[0].Name)
	}
	if msg.Question[0].Qtype != qtype {
		t.Errorf("question type should be %d, got %d", qtype, msg.Question[0].Qtype)
	}

	// Should have EDNS0
	opt := msg.IsEdns0()
	if opt == nil {
		t.Error("message should have EDNS0 OPT record")
	}

	// Test with cookies
	msg = em.prepareDNSMessage(qname, qtype, true, serverAddr)
	opt = msg.IsEdns0()
	if opt == nil {
		t.Error("message with cookies should have EDNS0 OPT record")
	}

	// Check for cookie option
	hasCookie := false
	for _, option := range opt.Option {
		if _, ok := option.(*dns.EDNS0_COOKIE); ok {
			hasCookie = true
			break
		}
	}
	if !hasCookie {
		t.Error("message should have DNS cookie when requested")
	}
}

// Test DNS cookie handling
func TestDNSCookieHandling(t *testing.T) {
	r := &Recursive{
		mu:            sync.RWMutex{},
		clientCookie:  "client12",
		serverCookies: make(map[netip.Addr]*serverCookie),
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	serverAddr := netip.MustParseAddr("8.8.8.8")

	// Test adding DNS cookie to message
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)

	em.addDNSCookie(msg, serverAddr)

	cookie := GetDNSCookie(msg)
	if !strings.HasPrefix(cookie, "client12") {
		t.Errorf("cookie should start with client cookie, got %s", cookie)
	}

	// Test processing cookie response
	response := new(dns.Msg)
	response.SetQuestion("example.org.", dns.TypeA)

	// Add server cookie to response
	SetDNSCookie(response, "client12server34")

	em.processCookieResponse(response, serverAddr)

	// Check that server cookie was stored
	stored, exists := r.getServerCookie(serverAddr)
	if !exists {
		t.Error("server cookie should be stored")
	}
	if stored != "server34" {
		t.Errorf("stored server cookie should be 'server34', got %s", stored)
	}
}

// Test network error handling
func TestNetworkErrorHandling(t *testing.T) {
	networkErrors := newNetworkErrorManager()
	r := &Recursive{
		networkErrors: networkErrors,
		mu:            sync.RWMutex{},
		config: &resolverConfig{
			useIPv6: true,
			useUDP:  true,
		},
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	addr := netip.MustParseAddr("192.0.2.1")
	testErr := errors.New("connection refused")

	// Test error handling
	err := em.handleNetworkError("udp", addr, "dial", testErr)

	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Error("should return NetworkError")
	}

	if netErr.Addr != addr {
		t.Errorf("NetworkError should have correct address, got %v", netErr.Addr)
	}
	if netErr.Protocol != "udp" {
		t.Errorf("NetworkError should have correct protocol, got %s", netErr.Protocol)
	}
	if netErr.Operation != "dial" {
		t.Errorf("NetworkError should have correct operation, got %s", netErr.Operation)
	}
	if !errors.Is(netErr.Err, testErr) {
		t.Error("NetworkError should wrap original error")
	}
}

// Test IPv6 disabling logic
func TestIPv6DisablingLogic(t *testing.T) {
	r := &Recursive{
		mu: sync.RWMutex{},
		config: &resolverConfig{
			useIPv6: true,
			rootServers: []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
			},
		},
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	// Test IPv6 unreachable error
	unreachableErr := errors.New("network is unreachable")
	disabled := em.tryDisableIPv6(unreachableErr)

	if !disabled {
		t.Error("should disable IPv6 for unreachable error")
	}
	if r.config.useIPv6 {
		t.Error("IPv6 should be disabled")
	}
	if len(r.config.rootServers) != 1 {
		t.Error("IPv6 root servers should be removed")
	}
	if !r.config.rootServers[0].Is4() {
		t.Error("remaining root server should be IPv4")
	}

	// Test that other errors don't disable IPv6
	r.config.useIPv6 = true
	timeoutErr := errors.New("timeout")
	disabled = em.tryDisableIPv6(timeoutErr)

	if disabled {
		t.Error("should not disable IPv6 for timeout error")
	}
}

// Test UDP disabling logic
func TestUDPDisablingLogic(t *testing.T) {
	r := &Recursive{
		mu: sync.RWMutex{},
		config: &resolverConfig{
			useUDP: true,
		},
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	// Test UDP not implemented error
	notImplErr := &net.OpError{
		Op:  "dial",
		Net: "udp",
		Err: errors.New("protocol not supported"),
	}
	disabled := em.tryDisableUDP(notImplErr)

	if !disabled {
		t.Error("should disable UDP for protocol not supported error")
	}
	if r.config.useUDP {
		t.Error("UDP should be disabled")
	}

	// Test that timeout errors don't disable UDP
	r.config.useUDP = true
	timeoutErr := &net.OpError{
		Op:      "dial",
		Net:     "udp",
		Timeout: true,
	}
	disabled = em.tryDisableUDP(timeoutErr)

	if disabled {
		t.Error("should not disable UDP for timeout error")
	}
}

// Test query execution with mock dialer
func TestQueryExecution(t *testing.T) {
	dialer := newMockDialer()
	networkErrors := newNetworkErrorManager()

	r := &Recursive{
		ContextDialer: dialer,
		networkErrors: networkErrors,
		mu:            sync.RWMutex{},
		config: &resolverConfig{
			useUDP:  true,
			useIPv4: true,
		},
		clientCookie:  "test1234",
		serverCookies: make(map[netip.Addr]*serverCookie),
	}

	cache := newMockCache()
	qc := &queryContext{
		recursive: r,
		cache:     cache,
	}

	serverAddr := netip.MustParseAddr("8.8.8.8")
	qname := "example.org."
	qtype := dns.TypeA

	// Create a mock DNS response
	response := new(dns.Msg)
	response.SetQuestion(qname, qtype)
	response.Rcode = dns.RcodeSuccess
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: qtype, Class: dns.ClassINET, Ttl: 300},
			A:   netip.MustParseAddr("192.0.2.1").AsSlice(),
		},
	}

	// Pack the response for the mock connection
	packed, err := response.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	// Set up mock connection with response data
	target := netip.AddrPortFrom(serverAddr, DefaultDNSPort).String()
	conn := newMockConnection()
	conn.readData = packed
	dialer.connections[target] = conn

	// Execute query
	result, err := qc.performDNSQuery(context.Background(), serverAddr, qname, qtype)

	if err != nil {
		t.Errorf("query should succeed: %v", err)
	}
	if result == nil {
		t.Error("should return DNS response")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("response should be successful, got %s", dns.RcodeToString[result.Rcode])
	}
	if len(result.Answer) != 1 {
		t.Errorf("should have 1 answer, got %d", len(result.Answer))
	}
}

// Test query with dial failure
func TestQueryWithDialFailure(t *testing.T) {
	dialer := newMockDialer()
	networkErrors := newNetworkErrorManager()

	r := &Recursive{
		ContextDialer: dialer,
		networkErrors: networkErrors,
		mu:            sync.RWMutex{},
		config: &resolverConfig{
			useUDP:  true,
			useIPv4: true,
		},
	}

	qc := &queryContext{
		recursive: r,
	}

	serverAddr := netip.MustParseAddr("8.8.8.8")
	target := netip.AddrPortFrom(serverAddr, DefaultDNSPort).String()

	// Set up dial failure
	dialErr := errors.New("connection refused")
	dialer.dialErrors[target] = dialErr

	// Execute query
	result, err := qc.performDNSQuery(context.Background(), serverAddr, "example.org.", dns.TypeA)

	if err == nil {
		t.Error("query should fail with dial error")
	}
	if result != nil {
		t.Error("should not return result on dial failure")
	}

	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Error("should return NetworkError on dial failure")
	}
}

// Test logging functionality
func TestExchangeManagerLogging(t *testing.T) {
	var logOutput strings.Builder

	r := &Recursive{}
	qc := &queryContext{
		logWriter: &logOutput,
		startTime: time.Now(),
	}
	em := newExchangeManager(r, qc)

	serverAddr := netip.MustParseAddr("8.8.8.8")

	// Test query attempt logging
	em.logQueryAttempt("udp4", serverAddr, "example.org.", dns.TypeA)

	output := logOutput.String()
	if !strings.Contains(output, "SENDING") {
		t.Error("should log query attempt")
	}
	if !strings.Contains(output, "8.8.8.8") {
		t.Error("should log server address")
	}
	if !strings.Contains(output, "example.org.") {
		t.Error("should log query name")
	}

	// Test response logging
	logOutput.Reset()

	response := new(dns.Msg)
	response.SetQuestion("example.org.", dns.TypeA)
	response.Rcode = dns.RcodeSuccess
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   netip.MustParseAddr("192.0.2.1").AsSlice(),
		},
	}

	em.logQueryResponse(response, 50*time.Millisecond, serverAddr, 100*time.Millisecond)

	output = logOutput.String()
	if !strings.Contains(output, "NOERROR") {
		t.Error("should log response code")
	}
	if !strings.Contains(output, "[1+0+0") {
		t.Error("should log record counts")
	}
}

// Test client cookie retrieval
func TestClientCookieRetrieval(t *testing.T) {
	clientCookie := "testcookie123"
	r := &Recursive{
		mu:           sync.RWMutex{},
		clientCookie: clientCookie,
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	retrieved := em.getClientCookie()
	if retrieved != clientCookie {
		t.Errorf("should retrieve client cookie, got %s, want %s", retrieved, clientCookie)
	}
}

// Benchmark exchange manager operations
func BenchmarkExchangeManager(b *testing.B) {
	r := &Recursive{
		mu:            sync.RWMutex{},
		clientCookie:  "test1234",
		serverCookies: make(map[netip.Addr]*serverCookie),
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	serverAddr := netip.MustParseAddr("8.8.8.8")

	b.Run("PrepareDNSMessage", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = em.prepareDNSMessage("example.org.", dns.TypeA, true, serverAddr)
		}
	})

	b.Run("GetNetworkString", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = em.getNetworkString("udp", serverAddr)
		}
	})

	b.Run("GetClientCookie", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = em.getClientCookie()
		}
	})
}

// Test error handling with different error types
func TestExchangeErrorHandling(t *testing.T) {
	networkErrors := newNetworkErrorManager()
	r := &Recursive{
		networkErrors: networkErrors,
		mu:            sync.RWMutex{},
		config: &resolverConfig{
			useIPv6: true,
			useUDP:  true,
		},
	}
	qc := &queryContext{recursive: r}
	em := newExchangeManager(r, qc)

	addr := netip.MustParseAddr("192.0.2.1")

	testCases := []struct {
		name     string
		err      error
		protocol string
		should   string
	}{
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			protocol: "udp",
			should:   "record error",
		},
		{
			name:     "timeout",
			err:      errors.New("timeout"),
			protocol: "tcp",
			should:   "record error",
		},
		{
			name:     "unreachable",
			err:      errors.New("network is unreachable"),
			protocol: "udp",
			should:   "record error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := em.handleNetworkError(tc.protocol, addr, "dial", tc.err)

			var netErr *NetworkError
			if !errors.As(err, &netErr) {
				t.Error("should return NetworkError")
			}

			if netErr.Operation != "dial" {
				t.Errorf("should record correct operation, got %s", netErr.Operation)
			}

			if !errors.Is(netErr.Err, tc.err) {
				t.Error("should wrap original error")
			}
		})
	}
}
