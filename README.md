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
[0      0] DELEGATION QUERY "www.microsoft.com."
[0      1]  SENDING udp4: @199.7.83.42 NS "com." => NOERROR [0+13+27 A/N/E] (4ms, 1527 bytes)
[5      1]  SENDING udp4: @192.5.6.30 NS "microsoft.com." => NOERROR [0+4+2 A/N/E] (27ms, 267 bytes)
[32     1]  SENDING udp4: @150.171.10.39 NS "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (13ms, 110 bytes AUTH)
[46     0] DELEGATION ANSWER "www.microsoft.com.": NOERROR with 1 servers
[46     0] QUERY A "www.microsoft.com." from 1 servers
[46     1]  SENDING udp4: @150.171.10.39 A "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (13ms, 110 bytes AUTH)
[60     1]  CNAME @150.171.10.39 A "www.microsoft.com." => "www.microsoft.com-c-3.edgekey.net."
[60     1]  DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net."
[60     2]   SENDING udp4: @199.7.83.42 NS "net." => NOERROR [0+13+27 A/N/E] (4ms, 1527 bytes)
[64     2]   SENDING udp4: @192.5.6.30 NS "edgekey.net." => NOERROR [0+8+17 A/N/E] (24ms, 943 bytes)
[88     2]   SENDING udp4: @23.61.199.64 NS "com-c-3.edgekey.net." => NOERROR [0+1+1 A/N/E] (3ms, 132 bytes AUTH)
[91     2]   SENDING udp4: @23.61.199.64 NS "microsoft.com-c-3.edgekey.net." => NOERROR [0+1+1 A/N/E] (3ms, 142 bytes AUTH)
[94     2]   SENDING udp4: @23.61.199.64 NS "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (3ms, 165 bytes AUTH)
[97     1]  DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.": NOERROR with 16 servers
[97     1]  QUERY A "www.microsoft.com-c-3.edgekey.net." from 16 servers
[97     2]   SENDING udp4: @23.61.199.64 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (2ms, 165 bytes AUTH)
[99     2]   CNAME @23.61.199.64 A "www.microsoft.com-c-3.edgekey.net." => "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net."
[99     2]   DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net."
[99     3]    CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[99     3]    SENDING udp4: @192.5.6.30 NS "akadns.net." => NOERROR [0+9+11 A/N/E] (25ms, 807 bytes)
[125    3]    SENDING udp4: @2.16.40.130 NS "globalredir.akadns.net." => NOERROR [0+1+1 A/N/E] (29ms, 137 bytes AUTH)
[154    3]    SENDING udp4: @2.16.40.130 NS "net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (32ms, 111 bytes AUTH)
[186    3]    SENDING udp4: @2.16.40.130 NS "edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (25ms, 127 bytes AUTH)
[212    3]    SENDING udp4: @2.16.40.130 NS "com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (32ms, 143 bytes AUTH)
[244    3]    SENDING udp4: @2.16.40.130 NS "microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (25ms, 163 bytes AUTH)
[270    3]    SENDING udp4: @2.16.40.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (28ms, 181 bytes AUTH)
[298    2]   DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.": NOERROR with 10 servers
[298    2]   QUERY A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." from 10 servers
[298    3]    SENDING udp4: @2.16.40.130 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (28ms, 181 bytes AUTH)
[327    3]    CNAME @2.16.40.130 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => "e13678.dscb.akamaiedge.net."
[327    3]    DELEGATION QUERY "e13678.dscb.akamaiedge.net."
[327    4]     CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[327    4]     SENDING udp4: @192.5.6.30 NS "akamaiedge.net." => NOERROR [0+8+10 A/N/E] (22ms, 771 bytes)
[348    4]     SENDING udp4: @2.16.40.192 NS "dscb.akamaiedge.net." => NOERROR [0+8+10 A/N/E] (32ms, 825 bytes)
[381    4]     SENDING udp4: @23.218.92.39 NS "e13678.dscb.akamaiedge.net." => NOERROR [0+1+1 A/N/E] (2ms, 152 bytes AUTH)
[384    3]    DELEGATION ANSWER "e13678.dscb.akamaiedge.net.": NOERROR with 9 servers
[384    3]    QUERY A "e13678.dscb.akamaiedge.net." from 9 servers
[384    4]     SENDING udp4: @23.218.92.39 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (3ms, 97 bytes AUTH)
[387    3]    ANSWER @23.218.92.39 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (97 bytes AUTH)
[387    2]   ANSWER @23.218.92.39 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [2+0+2 A/N/E] (234 bytes AUTH)
[387    1]  ANSWER @23.218.92.39 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [3+0+3 A/N/E] (325 bytes AUTH)
[387    0] ANSWER @23.218.92.39 A "www.microsoft.com." => NOERROR [4+0+4 A/N/E] (384 bytes AUTH)

;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @23.218.92.39 A www.microsoft.com
;; opcode: QUERY, status: NOERROR, id: 55642
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

;; GZPACK: H4sIAAAAAAAA/7oZ1cLAwMjAwsDAwMJcXl7OmZuZXJRfnJ9WwpycnwuSYsQmzMrAyMDAJ8CgjCrJnpyfq5usa8yempKemp1ayZyXWsJAhBKIecwtDFaEFXOn5+QnJeYUpaZkFrElZiem5BUTaQ0unXDbZdhSDY3NzC1YUoqTk7gSsxNzEzNB+sGq8MmBgomBgUGEgYVJ6FgqA4MmywUGKNAUYMDHBAQAAP//DDE9MYABAAA=
;; SERVER: 23.218.92.39
;; CACHE: size 22, hit ratio 8.33%
```
