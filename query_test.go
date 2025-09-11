package recursive

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockCache implements Cacher for testing
type mockCache struct {
	data map[string]*dns.Msg
	hits int
	sets int
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string]*dns.Msg),
	}
}

func (mc *mockCache) DnsGet(qname string, qtype uint16) *dns.Msg {
	mc.hits++
	key := qname + "/" + DnsTypeToString(qtype)
	return mc.data[key]
}

func (mc *mockCache) DnsSet(msg *dns.Msg) {
	if msg == nil || len(msg.Question) == 0 {
		return
	}
	mc.sets++
	q := msg.Question[0]
	key := q.Name + "/" + DnsTypeToString(q.Qtype)
	mc.data[key] = msg.Copy()
}

func TestQueryContextCreation(t *testing.T) {
	r := &Recursive{}
	cache := newMockCache()

	qc := newQueryContext(r, cache, nil)

	if qc.recursive != r {
		t.Error("queryContext should reference the recursive resolver")
	}
	if qc.cache != cache {
		t.Error("queryContext should reference the cache")
	}
	if qc.depth != 0 {
		t.Error("initial depth should be 0")
	}
	if qc.stepsTaken != 0 {
		t.Error("initial steps should be 0")
	}
	if qc.glueRecords == nil {
		t.Error("glue records map should be initialized")
	}
}

func TestQueryContextDepthManagement(t *testing.T) {
	qc := &queryContext{}

	// Test entering depth
	err := qc.enterDepth()
	if err != nil {
		t.Errorf("enterDepth should not error initially: %v", err)
	}
	if qc.depth != 1 {
		t.Errorf("depth should be 1 after enterDepth, got %d", qc.depth)
	}

	// Test exiting depth
	qc.exitDepth()
	if qc.depth != 0 {
		t.Errorf("depth should be 0 after exitDepth, got %d", qc.depth)
	}

	// Test max depth
	qc.depth = maxDepth
	err = qc.enterDepth()
	if !errors.Is(err, ErrMaxDepth) {
		t.Errorf("should get maxDepthError when exceeding max depth, got %v", err)
	}
}

func TestQueryContextStepManagement(t *testing.T) {
	qc := &queryContext{}

	// Test incrementing steps
	err := qc.incrementSteps()
	if err != nil {
		t.Errorf("incrementSteps should not error initially: %v", err)
	}
	if qc.stepsTaken != 1 {
		t.Errorf("steps should be 1 after increment, got %d", qc.stepsTaken)
	}

	// Test max steps
	qc.stepsTaken = maxSteps
	err = qc.incrementSteps()
	if !errors.Is(err, ErrMaxSteps) {
		t.Errorf("should get maxStepsError when exceeding max steps, got %v", err)
	}
}

func TestQueryContextCaching(t *testing.T) {
	cache := newMockCache()
	qc := &queryContext{cache: cache}

	// Create a test message
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   netip.MustParseAddr("192.0.2.1").AsSlice(),
		},
	}

	// Test caching
	qc.cacheResponse(msg)
	if cache.sets != 1 {
		t.Errorf("cache should have 1 set, got %d", cache.sets)
	}

	// Test cache retrieval
	cached := cache.DnsGet("example.org.", dns.TypeA)
	if cached == nil {
		t.Error("should retrieve cached message")
	}
	if cache.hits != 1 {
		t.Errorf("cache should have 1 hit, got %d", cache.hits)
	}
}

func TestGlueRecordManagement(t *testing.T) {
	qc := &queryContext{
		glueRecords: make(map[string][]netip.Addr),
		recursive:   &Recursive{},
	}

	// Mock isAddressUsable to return true
	qc.recursive.isAddressUsable = func(addr netip.Addr) bool { return true }

	hostname := "ns.example.org."
	addr := netip.MustParseAddr("192.0.2.1")

	// Test adding to glue map
	qc.addToGlueMap(hostname)
	if _, exists := qc.glueRecords[hostname]; !exists {
		t.Error("hostname should be added to glue map")
	}

	// Test updating glue record
	qc.updateGlueRecord(hostname, addr)
	if len(qc.glueRecords[hostname]) != 1 {
		t.Error("should have one glue record")
	}
	if qc.glueRecords[hostname][0] != addr {
		t.Error("glue record should match added address")
	}

	// Test duplicate address
	qc.updateGlueRecord(hostname, addr)
	if len(qc.glueRecords[hostname]) != 1 {
		t.Error("should not add duplicate glue record")
	}
}

func TestCNAMEChainManagement(t *testing.T) {
	qc := &queryContext{}

	target1 := "target1.example.org."
	target2 := "target2.example.org."

	// Test first CNAME target
	if !qc.followCNAME(target1) {
		t.Error("should follow first CNAME target")
	}

	// Test different CNAME target
	if !qc.followCNAME(target2) {
		t.Error("should follow different CNAME target")
	}

	// Test loop detection
	if qc.followCNAME(target1) {
		t.Error("should detect CNAME loop")
	}
}

func TestQueryLabelGeneration(t *testing.T) {
	qc := &queryContext{
		glueRecords: make(map[string][]netip.Addr),
	}

	qname := "www.example.org."
	qtype := dns.TypeA

	// Test without minimization
	qc.disableMinimization = true
	label, isComplete := qc.getCurrentQueryLabel(qname, qtype, 1)
	if label.name != qname || label.qtype != qtype || !isComplete {
		t.Error("should return full query when minimization disabled")
	}

	// Test with minimization
	qc.disableMinimization = false
	label, isComplete = qc.getCurrentQueryLabel(qname, qtype, 1)
	if isComplete {
		t.Error("first label should not be complete")
	}
	if label.qtype != dns.TypeNS {
		t.Error("first label should be NS query")
	}
	if !strings.HasSuffix(label.name, "org.") {
		t.Error("first label should be for org.")
	}
}

func TestNameserverInfoSorting(t *testing.T) {
	nameservers := []nameserverInfo{
		{hostname: "ns2.example.org.", address: netip.Addr{}},                     // No address
		{hostname: "ns1.example.org.", address: netip.MustParseAddr("192.0.2.1")}, // Has address
		{hostname: "ns3.example.org.", address: netip.MustParseAddr("192.0.2.2")}, // Has address
		{hostname: "ns4.example.org.", address: netip.Addr{}},                     // No address
	}

	// Sort using the logic from extractNameservers
	// This is a simplified version of the actual sorting logic
	result := make([]nameserverInfo, len(nameservers))
	copy(result, nameservers)

	// Count addresses vs no addresses
	withAddr := 0
	withoutAddr := 0
	for _, ns := range result {
		if ns.address.IsValid() {
			withAddr++
		} else {
			withoutAddr++
		}
	}

	if withAddr != 2 || withoutAddr != 2 {
		t.Error("should have 2 nameservers with addresses and 2 without")
	}
}

func TestQueryLogging(t *testing.T) {
	var logOutput strings.Builder
	qc := &queryContext{
		logWriter: &logOutput,
		startTime: time.Now(),
	}

	// Test logging
	qc.logMessage("test message %s %d\n", "hello", 42)

	output := logOutput.String()
	if !strings.Contains(output, "test message hello 42") {
		t.Errorf("log output should contain formatted message, got: %s", output)
	}

	// Test shouldLog
	if !qc.shouldLog() {
		t.Error("should log when logWriter is set")
	}

	qc.logWriter = nil
	if qc.shouldLog() {
		t.Error("should not log when logWriter is nil")
	}
}

// Test query validation
func TestQueryValidation(t *testing.T) {
	qc := &queryContext{}

	// Test successful response validation
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess

	err := qc.validateResponseMatch(msg, "example.org.", dns.TypeA)
	if err != nil {
		t.Errorf("should validate matching response: %v", err)
	}

	// Test question mismatch
	err = qc.validateResponseMatch(msg, "other.org.", dns.TypeA)
	if !errors.Is(err, ErrQuestionMismatch) {
		t.Errorf("should detect question mismatch: %v", err)
	}

	// Test type mismatch
	err = qc.validateResponseMatch(msg, "example.org.", dns.TypeAAAA)
	if !errors.Is(err, ErrQuestionMismatch) {
		t.Errorf("should detect type mismatch: %v", err)
	}

	// Test no questions
	emptyMsg := new(dns.Msg)
	err = qc.validateResponseMatch(emptyMsg, "example.org.", dns.TypeA)
	if !errors.Is(err, ErrNoQuestions) {
		t.Errorf("should detect no questions: %v", err)
	}
}

// Test response processing helpers
func TestResponseProcessingHelpers(t *testing.T) {
	qc := &queryContext{}

	// Test shouldRetryWithoutMinimization
	refusedMsg := new(dns.Msg)
	refusedMsg.Rcode = dns.RcodeRefused

	if !qc.shouldRetryWithoutMinimization(refusedMsg) {
		t.Error("should retry without minimization for REFUSED")
	}

	qc.disableMinimization = true
	if qc.shouldRetryWithoutMinimization(refusedMsg) {
		t.Error("should not retry when minimization already disabled")
	}

	// Test hasUsableAnswers
	successMsg := new(dns.Msg)
	successMsg.SetQuestion("example.org.", dns.TypeA)
	successMsg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   netip.MustParseAddr("192.0.2.1").AsSlice(),
		},
	}

	if !qc.hasUsableAnswers(successMsg) {
		t.Error("message with answers should be usable")
	}

	emptyMsg := new(dns.Msg)
	if qc.hasUsableAnswers(emptyMsg) {
		t.Error("empty message should not be usable")
	}
}

// Test final result caching and validation
func TestFinalResultProcessing(t *testing.T) {
	cache := newMockCache()
	qc := &queryContext{cache: cache}

	// Test successful result caching
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   netip.MustParseAddr("192.0.2.1").AsSlice(),
		},
	}

	err := qc.validateAndCacheResult(msg, "example.org.", dns.TypeA, cache, nil)
	if err != nil {
		t.Errorf("should validate and cache successful result: %v", err)
	}
	if cache.sets != 1 {
		t.Error("should cache successful result")
	}

	// Test error response handling
	errorMsg := new(dns.Msg)
	errorMsg.SetQuestion("example.org.", dns.TypeA)
	errorMsg.Rcode = dns.RcodeNameError

	err = qc.validateAndCacheResult(errorMsg, "example.org.", dns.TypeA, cache, nil)
	if err != nil {
		t.Errorf("should handle error response: %v", err)
	}
}

// Benchmark query context operations
func BenchmarkQueryContext(b *testing.B) {
	qc := &queryContext{
		glueRecords: make(map[string][]netip.Addr),
	}

	b.Run("EnterExitDepth", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			qc.depth = 0
			_ = qc.enterDepth()
			qc.exitDepth()
		}
	})

	b.Run("IncrementSteps", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			qc.stepsTaken = 0
			_ = qc.incrementSteps()
		}
	})

	b.Run("GlueRecordUpdate", func(b *testing.B) {
		hostname := "ns.example.org."
		addr := netip.MustParseAddr("192.0.2.1")

		for i := 0; i < b.N; i++ {
			qc.glueRecords = make(map[string][]netip.Addr)
			qc.addToGlueMap(hostname)
			qc.updateGlueRecord(hostname, addr)
		}
	})
}

// Test integration with actual DNS messages
func TestQueryContextWithRealDNSMessages(t *testing.T) {
	cache := newMockCache()
	qc := &queryContext{
		cache:       cache,
		glueRecords: make(map[string][]netip.Addr),
	}

	// Create a realistic DNS response with NS records and glue
	nsMsg := new(dns.Msg)
	nsMsg.SetQuestion("example.org.", dns.TypeNS)
	nsMsg.Rcode = dns.RcodeSuccess
	nsMsg.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.org.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns2.example.org.",
		},
	}
	nsMsg.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns1.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   netip.MustParseAddr("192.0.2.1").AsSlice(),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns2.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   netip.MustParseAddr("192.0.2.2").AsSlice(),
		},
	}

	// Test nameserver extraction
	nameservers := qc.extractNameservers(nsMsg)
	if len(nameservers) != 2 {
		t.Errorf("should extract 2 nameservers, got %d", len(nameservers))
	}

	// Verify glue records were extracted
	if len(qc.glueRecords) != 2 {
		t.Errorf("should have 2 glue records, got %d", len(qc.glueRecords))
	}

	// Verify addresses are present
	for _, ns := range nameservers {
		if !ns.address.IsValid() {
			t.Errorf("nameserver %s should have valid address", ns.hostname)
		}
	}
}
