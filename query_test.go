package recursive

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDnameRecords(t *testing.T) {
	t.Parallel()

	rrs := []dns.RR{}
	build := []string{
		"ExAmPlE.cOm. 3600 IN DNAME target.example.net.",
		"www.example.com. 3600 IN CNAME alias.example.net.",
		"irrelevant.example.com. 3600 IN A 192.0.2.10",
	}
	for _, text := range build {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("failed to build RR %q: %v", text, err)
		}
		rrs = append(rrs, rr)
	}

	records := dnameRecords(rrs, "WWW.EXAMPLE.COM.")

	if len(records) != 2 {
		t.Fatalf("dnameRecords returned %d entries", len(records))
	}
	if _, ok := records[0].(*dns.DNAME); !ok {
		t.Fatalf("expected first record to be DNAME, got %T", records[0])
	}
	if _, ok := records[1].(*dns.CNAME); !ok {
		t.Fatalf("expected second record to be CNAME, got %T", records[1])
	}
}
