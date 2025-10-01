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

The resolver can log query details. To protect privacy, logs only include the
first few characters of the client and server cookie values.

Some servers don't handle QNAME minimization well. In that case, we fall back
to normal resolution.

You can have the library generate a detailed log:

```
$ go run ./cmd/cli -debug A www.microsoft.com
[0      0] DELEGATION QUERY "com." from 13 servers
[0      1]  SENDING udp4: @192.36.148.17 NS "com." SETCOOKIE:"...7d6ab" => NOERROR [0+13+27 A/N/E] (2ms, 1555 bytes)
[3      0] DELEGATION ANSWER "com.": NOERROR with 13 records
[3      0] DELEGATION QUERY "microsoft.com." from 26 servers
[3      1]  SENDING udp4: @192.5.6.30 NS "microsoft.com." => NOERROR [0+4+2 A/N/E] (23ms, 267 bytes)
[27     0] DELEGATION ANSWER "microsoft.com.": NOERROR with 4 records
[27     0] DELEGATION QUERY "www.microsoft.com." from 1 servers
[27     1]  SENDING udp4: @150.171.10.39 NS "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (12ms, 110 bytes AUTH)
[39     0] DELEGATION ANSWER "www.microsoft.com.": NOERROR with 0 records
[39     0] QUERY A "www.microsoft.com." from 1 servers
[39     1]  SENDING udp4: @150.171.10.39 A "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (12ms, 110 bytes AUTH)
[52     1]  CNAME @150.171.10.39 A "www.microsoft.com." => "www.microsoft.com-c-3.edgekey.net."
[52     1]  DELEGATION QUERY "net." from 13 servers
[52     2]   SENDING udp4: @192.36.148.17 NS "net." COOKIE:"...e92c8|...7d6ab" => NOERROR [0+13+27 A/N/E] (2ms, 1555 bytes)
[54     1]  DELEGATION ANSWER "net.": NOERROR with 13 records
[54     1]  DELEGATION QUERY "edgekey.net." from 26 servers
[54     2]   SENDING udp4: @192.5.6.30 NS "edgekey.net." => NOERROR [0+8+17 A/N/E] (23ms, 943 bytes)
[77     1]  DELEGATION ANSWER "edgekey.net.": NOERROR with 8 records
[77     1]  DELEGATION QUERY "com-c-3.edgekey.net." from 16 servers
[77     2]   SENDING udp4: @23.61.199.64 NS "com-c-3.edgekey.net." => NOERROR [0+1+1 A/N/E] (2ms, 132 bytes AUTH)
[80     1]  DELEGATION ANSWER "com-c-3.edgekey.net.": NOERROR with 0 records
[80     1]  DELEGATION QUERY "microsoft.com-c-3.edgekey.net." from 16 servers
[80     2]   SENDING udp4: @23.61.199.64 NS "microsoft.com-c-3.edgekey.net." => NOERROR [0+1+1 A/N/E] (2ms, 142 bytes AUTH)
[81     1]  DELEGATION ANSWER "microsoft.com-c-3.edgekey.net.": NOERROR with 0 records
[81     1]  DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net." from 16 servers
[81     2]   SENDING udp4: @23.61.199.64 NS "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (2ms, 165 bytes AUTH)
[84     1]  DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.": NOERROR with 0 records
[84     1]  QUERY A "www.microsoft.com-c-3.edgekey.net." from 16 servers
[84     2]   SENDING udp4: @23.61.199.64 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (2ms, 165 bytes AUTH)
[85     2]   CNAME @23.61.199.64 A "www.microsoft.com-c-3.edgekey.net." => "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net."
[85     2]   DELEGATION QUERY "net." from 13 servers
[85     3]    CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1555 bytes)
[85     2]   DELEGATION ANSWER "net.": NOERROR with 13 records
[85     2]   DELEGATION QUERY "akadns.net." from 26 servers
[85     3]    SENDING udp4: @192.5.6.30 NS "akadns.net." => NOERROR [0+9+11 A/N/E] (25ms, 807 bytes)
[111    2]   DELEGATION ANSWER "akadns.net.": NOERROR with 9 records
[111    2]   DELEGATION QUERY "globalredir.akadns.net." from 10 servers
[111    3]    SENDING udp4: @2.16.40.130 NS "globalredir.akadns.net." => NOERROR [0+1+1 A/N/E] (31ms, 137 bytes AUTH)
[142    2]   DELEGATION ANSWER "globalredir.akadns.net.": NOERROR with 0 records
[142    2]   DELEGATION QUERY "net.globalredir.akadns.net." from 10 servers
[142    3]    SENDING udp4: @2.16.40.130 NS "net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 111 bytes AUTH)
[173    2]   DELEGATION ANSWER "net.globalredir.akadns.net.": NOERROR with 0 records
[173    2]   DELEGATION QUERY "edgekey.net.globalredir.akadns.net." from 10 servers
[173    3]    SENDING udp4: @2.16.40.130 NS "edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 127 bytes AUTH)
[205    2]   DELEGATION ANSWER "edgekey.net.globalredir.akadns.net.": NOERROR with 0 records
[205    2]   DELEGATION QUERY "com-c-3.edgekey.net.globalredir.akadns.net." from 10 servers
[205    3]    SENDING udp4: @2.16.40.130 NS "com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 143 bytes AUTH)
[236    2]   DELEGATION ANSWER "com-c-3.edgekey.net.globalredir.akadns.net.": NOERROR with 0 records
[236    2]   DELEGATION QUERY "microsoft.com-c-3.edgekey.net.globalredir.akadns.net." from 10 servers
[236    3]    SENDING udp4: @2.16.40.130 NS "microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (30ms, 163 bytes AUTH)
[266    2]   DELEGATION ANSWER "microsoft.com-c-3.edgekey.net.globalredir.akadns.net.": NOERROR with 0 records
[266    2]   DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." from 10 servers
[266    3]    SENDING udp4: @2.16.40.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 181 bytes AUTH)
[297    2]   DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.": NOERROR with 0 records
[297    2]   QUERY A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." from 10 servers
[297    3]    SENDING udp4: @2.16.40.130 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 181 bytes AUTH)
[328    3]    CNAME @2.16.40.130 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => "e13678.dscb.akamaiedge.net."
[328    3]    DELEGATION QUERY "net." from 13 servers
[328    4]     CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1555 bytes)
[328    3]    DELEGATION ANSWER "net.": NOERROR with 13 records
[329    3]    DELEGATION QUERY "akamaiedge.net." from 26 servers
[329    4]     SENDING udp4: @192.5.6.30 NS "akamaiedge.net." => NOERROR [0+8+10 A/N/E] (22ms, 771 bytes)
[351    3]    DELEGATION ANSWER "akamaiedge.net.": NOERROR with 8 records
[351    3]    DELEGATION QUERY "dscb.akamaiedge.net." from 9 servers
[351    4]     SENDING udp4: @2.16.40.192 NS "dscb.akamaiedge.net." => NOERROR [0+8+10 A/N/E] (31ms, 825 bytes)
[382    3]    DELEGATION ANSWER "dscb.akamaiedge.net.": NOERROR with 8 records
[382    3]    DELEGATION QUERY "e13678.dscb.akamaiedge.net." from 9 servers
[382    4]     SENDING udp4: @23.218.92.38 NS "e13678.dscb.akamaiedge.net." => NOERROR [0+1+1 A/N/E] (2ms, 152 bytes AUTH)
[384    3]    DELEGATION ANSWER "e13678.dscb.akamaiedge.net.": NOERROR with 0 records
[384    3]    QUERY A "e13678.dscb.akamaiedge.net." from 9 servers
[384    4]     SENDING udp4: @23.218.92.38 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (2ms, 97 bytes AUTH)
[386    3]    ANSWER @23.218.92.38 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (97 bytes AUTH)
[386    2]   ANSWER @23.218.92.38 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [2+0+2 A/N/E] (234 bytes AUTH)
[386    1]  ANSWER @23.218.92.38 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [3+0+3 A/N/E] (325 bytes AUTH)
[386    0] ANSWER @23.218.92.38 A "www.microsoft.com." => NOERROR [4+0+4 A/N/E] (384 bytes AUTH)

;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @23.218.92.38 A www.microsoft.com
;; opcode: QUERY, status: NOERROR, id: 819
;; flags: qr aa; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;www.microsoft.com.     IN       A

;; ANSWER SECTION:
www.microsoft.com.      3600    IN      CNAME   www.microsoft.com-c-3.edgekey.net.
www.microsoft.com-c-3.edgekey.net.      900     IN      CNAME   www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.
www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.       900     IN      CNAME   e13678.dscb.akamaiedge.net.
e13678.dscb.akamaiedge.net.     20      IN      A       2.18.198.101

;; ADDITIONAL SECTION:

;; GZPACK: H4sIAAAAAAAA/2I2bmFgYGRgYWBgYGEuLy/nzM1MLsovzk8rYU7OzwVJMWITZmVgZGDgE2BQRpVkT87P1U3WNWZPTUlPzU6tZM5LLWEgQgnEPOYWBivCirnTc/KTEnOKUlMyi9gSsxNT8oqJtAaXTrjtMmyphsZm5hYsKcXJSVyJ2Ym5iZkg/WBV+ORAwcTAwCDCwMIkdCyVgUGT5QIDFGgKMOBjAgIAAP//JkaWNYABAAA=
;; SERVER: 23.218.92.38
;; CACHE: size 22, hit ratio 8.33%
```
