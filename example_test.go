package recursive_test

import (
	"context"
	"fmt"
	"time"

	"github.com/linkdata/recursive"
	"github.com/miekg/dns"
)

func Example() {
	rec := recursive.New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	msg, _, err := rec.DnsResolve(ctx, "one.one.one.one", dns.TypeA)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(msg.Answer) > 0)
	// Output:
	// true
}
