[![build](https://github.com/linkdata/recursive/actions/workflows/build.yml/badge.svg)](https://github.com/linkdata/recursive/actions/workflows/build.yml)
[![coverage](https://github.com/linkdata/recursive/blob/coverage/main/badge.svg)](https://htmlpreview.github.io/?https://github.com/linkdata/recursive/blob/coverage/main/report.html)
[![goreport](https://goreportcard.com/badge/github.com/linkdata/recursive)](https://goreportcard.com/report/github.com/linkdata/recursive)
[![Docs](https://godoc.org/github.com/linkdata/recursive?status.svg)](https://godoc.org/github.com/linkdata/recursive)

# recursive

Recursive DNS resolver with QNAME minimization and optional cache.

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/linkdata/recursive"
	"github.com/miekg/dns"
)

func main() {
	rec := recursive.New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	msg, srv, err := rec.DnsResolve(ctx, "one.one.one.one", dns.TypeA)
	if err != nil {
		panic(err)
	}
	fmt.Println(msg)
    fmt.Println(";; SERVER ", srv)
}

```