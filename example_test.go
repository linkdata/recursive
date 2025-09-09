//go:build network
// +build network

package recursive_test

import (
	"context"
	"fmt"
	"time"

	"github.com/linkdata/recursive"
	"github.com/miekg/dns"
)

func Example() {
	// This example requires network access. Expect it to fail otherwise.
	rec := recursive.New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	msg, _, err := rec.DnsResolve(ctx, "one.one.one.one", dns.TypeA)
	if err == nil {
		fmt.Println(len(msg.Answer) > 0)
	} else {
		fmt.Println("failed to resolve one.one.one.one:", err)
	}
	// Output:
	// true
}
