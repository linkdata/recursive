package recursive

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestExchangeUsingMaxSteps(t *testing.T) {
	q := &query{Recursive: &Recursive{}}
	q.steps = maxSteps
	if _, err := q.exchangeUsing(context.Background(), "udp", false, netip.MustParseAddr("192.0.2.1"), "example.org.", dns.TypeA); !errors.Is(err, ErrMaxSteps) {
		t.Fatalf("expected ErrMaxSteps, got %v", err)
	}
}
