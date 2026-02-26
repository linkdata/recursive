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
[0      1]  SENDING udp4: @198.41.0.4 NS "com." => NOERROR [0+13+27 A/N/E] (9ms, 1527 bytes)
[9      1]  SENDING udp4: @192.33.14.30 NS "microsoft.com." => NOERROR [0+4+2 A/N/E] (42ms, 267 bytes)
[52     1]  GLUE QUERY [ns2-39.azure-dns.net. ns3-39.azure-dns.org. ns4-39.azure-dns.info.]
[52     2]   DELEGATION QUERY "ns2-39.azure-dns.net."
[52     3]    SENDING udp4: @198.41.0.4 NS "net." => NOERROR [0+13+27 A/N/E] (10ms, 1527 bytes)
[62     3]    SENDING udp4: @192.48.79.30 NS "azure-dns.net." ERROR: read udp 10.99.0.2:48348: i/o timeout
[2064   3]    SENDING tcp4: @192.48.79.30 +tcp NS "azure-dns.net." => NOERROR [0+4+9 A/N/E] (36ms, 566 bytes)
[2138   3]    SENDING udp4: @150.171.21.4 NS "ns2-39.azure-dns.net." => NOERROR [0+1+1 A/N/E] (10ms, 151 bytes AUTH)
[2148   2]   DELEGATION ANSWER "ns2-39.azure-dns.net.": NOERROR with 4 servers
[2148   2]   QUERY A "ns2-39.azure-dns.net." from 4 servers
[2148   3]    SENDING udp4: @150.171.21.4 A "ns2-39.azure-dns.net." => NOERROR [1+0+1 A/N/E] (6ms, 85 bytes AUTH)
[2155   2]   ANSWER @150.171.21.4 A "ns2-39.azure-dns.net." => NOERROR [1+0+1 A/N/E] (85 bytes AUTH)
[2155   2]   DELEGATION QUERY "ns3-39.azure-dns.org."
[2155   3]    SENDING udp4: @198.41.0.4 NS "org." => NOERROR [0+6+13 A/N/E] (27ms, 803 bytes)
[2182   3]    SENDING udp4: @199.19.56.1 NS "azure-dns.org." => NOERROR [0+4+9 A/N/E] (201ms, 566 bytes)
[2383   3]    SENDING udp4: @204.14.183.4 NS "ns3-39.azure-dns.org." => NOERROR [0+1+1 A/N/E] (6ms, 151 bytes AUTH)
[2389   2]   DELEGATION ANSWER "ns3-39.azure-dns.org.": NOERROR with 4 servers
[2389   2]   QUERY A "ns3-39.azure-dns.org." from 4 servers
[2389   3]    SENDING udp4: @204.14.183.4 A "ns3-39.azure-dns.org." => NOERROR [1+0+1 A/N/E] (6ms, 85 bytes AUTH)
[2395   2]   ANSWER @204.14.183.4 A "ns3-39.azure-dns.org." => NOERROR [1+0+1 A/N/E] (85 bytes AUTH)
[2395   2]   DELEGATION QUERY "ns4-39.azure-dns.info."
[2395   3]    SENDING udp4: @198.41.0.4 NS "info." => NOERROR [0+6+13 A/N/E] (10ms, 828 bytes)
[2405   3]    SENDING udp4: @199.254.31.1 NS "azure-dns.info." => NOERROR [0+4+9 A/N/E] (268ms, 583 bytes)
[2673   3]    SENDING udp4: @208.84.5.3 NS "ns4-39.azure-dns.info." => NOERROR [0+1+1 A/N/E] (14ms, 153 bytes AUTH)
[2687   2]   DELEGATION ANSWER "ns4-39.azure-dns.info.": NOERROR with 4 servers
[2687   2]   QUERY A "ns4-39.azure-dns.info." from 4 servers
[2687   3]    SENDING udp4: @208.84.5.3 A "ns4-39.azure-dns.info." => NOERROR [1+0+1 A/N/E] (14ms, 87 bytes AUTH)
[2702   2]   ANSWER @208.84.5.3 A "ns4-39.azure-dns.info." => NOERROR [1+0+1 A/N/E] (87 bytes AUTH)
[2702   1]  GLUE ANSWER [150.171.16.39 13.107.222.39 13.107.206.39]
[2702   1]  SENDING udp4: @13.107.222.39 NS "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (6ms, 110 bytes AUTH)
[2708   0] DELEGATION ANSWER "www.microsoft.com.": NOERROR with 4 servers
[2708   0] QUERY A "www.microsoft.com." from 4 servers
[2708   1]  SENDING udp4: @13.107.222.39 A "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (6ms, 110 bytes AUTH)
[2715   1]  CNAME @13.107.222.39 A "www.microsoft.com." => "www.microsoft.com-c-3.edgekey.net."
[2715   1]  DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net."
[2715   2]   CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[2715   2]   SENDING tcp4: @192.48.79.30 +tcp NS "edgekey.net." => NOERROR [0+8+17 A/N/E] (36ms, 943 bytes)
[2787   2]   SENDING udp4: @184.26.160.65 NS "com-c-3.edgekey.net." => NOERROR [0+1+1 A/N/E] (27ms, 132 bytes AUTH)
[2814   2]   DELEGATION RETRY without QNAME minimization
[2814   2]   SENDING udp4: @184.26.160.65 NS "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (27ms, 165 bytes AUTH)
[2841   1]  DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.": NOERROR with 8 servers
[2841   1]  QUERY A "www.microsoft.com-c-3.edgekey.net." from 8 servers
[2841   2]   SENDING udp4: @184.26.160.65 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (27ms, 165 bytes AUTH)
[2868   2]   CNAME @184.26.160.65 A "www.microsoft.com-c-3.edgekey.net." => "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net."
[2868   2]   DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net."
[2868   3]    CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[2868   3]    SENDING udp4: @192.55.83.30 NS "akadns.net." => NOERROR [0+9+11 A/N/E] (37ms, 807 bytes)
[2906   3]    GLUE QUERY [a28-129.akagtm.org. a18-128.akagtm.org. a42-130.akagtm.org. a7-130.akagtm.org.]
[2906   4]     DELEGATION QUERY "a28-129.akagtm.org."
[2906   5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[2906   5]      SENDING udp4: @199.249.120.1 NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (13ms, 717 bytes)
[2919   5]      SENDING udp4: @184.26.160.128 NS "a28-129.akagtm.org." => NOERROR [0+1+1 A/N/E] (27ms, 131 bytes AUTH)
[2946   4]     DELEGATION ANSWER "a28-129.akagtm.org.": NOERROR with 9 servers
[2946   4]     QUERY A "a28-129.akagtm.org." from 9 servers
[2946   5]      SENDING udp4: @184.26.160.128 A "a28-129.akagtm.org." => NOERROR [1+0+1 A/N/E] (26ms, 81 bytes AUTH)
[2973   4]     ANSWER @184.26.160.128 A "a28-129.akagtm.org." => NOERROR [1+0+1 A/N/E] (81 bytes AUTH)
[2973   4]     DELEGATION QUERY "a18-128.akagtm.org."
[2973   5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[2973   5]      CACHED: NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (717 bytes)
[2973   5]      SENDING udp4: @2.17.46.130 NS "a18-128.akagtm.org." => NOERROR [0+1+1 A/N/E] (30ms, 131 bytes AUTH)
[3002   4]     DELEGATION ANSWER "a18-128.akagtm.org.": NOERROR with 9 servers
[3002   4]     QUERY A "a18-128.akagtm.org." from 9 servers
[3002   5]      SENDING udp4: @2.17.46.130 A "a18-128.akagtm.org." => NOERROR [1+0+1 A/N/E] (30ms, 81 bytes AUTH)
[3033   4]     ANSWER @2.17.46.130 A "a18-128.akagtm.org." => NOERROR [1+0+1 A/N/E] (81 bytes AUTH)
[3033   4]     DELEGATION QUERY "a42-130.akagtm.org."
[3033   5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[3033   5]      CACHED: NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (717 bytes)
[3033   5]      SENDING udp4: @184.26.160.128 NS "a42-130.akagtm.org." => NOERROR [0+1+1 A/N/E] (27ms, 131 bytes AUTH)
[3059   4]     DELEGATION ANSWER "a42-130.akagtm.org.": NOERROR with 9 servers
[3059   4]     QUERY A "a42-130.akagtm.org." from 9 servers
[3059   5]      SENDING udp4: @184.26.160.128 A "a42-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (26ms, 81 bytes AUTH)
[3085   4]     ANSWER @184.26.160.128 A "a42-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (81 bytes AUTH)
[3085   4]     DELEGATION QUERY "a7-130.akagtm.org."
[3085   5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[3085   5]      CACHED: NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (717 bytes)
[3086   5]      SENDING udp4: @23.61.199.128 NS "a7-130.akagtm.org." => NOERROR [0+1+1 A/N/E] (31ms, 130 bytes AUTH)
[3117   4]     DELEGATION ANSWER "a7-130.akagtm.org.": NOERROR with 9 servers
[3117   4]     QUERY A "a7-130.akagtm.org." from 9 servers
[3117   5]      SENDING udp4: @23.61.199.128 A "a7-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (28ms, 79 bytes AUTH)
[3145   4]     ANSWER @23.61.199.128 A "a7-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (79 bytes AUTH)
[3145   3]    GLUE ANSWER [95.100.173.129 95.101.36.128 184.28.92.130 23.61.199.130]
[3145   3]    SENDING udp4: @193.108.88.128 NS "globalredir.akadns.net." => NOERROR [0+1+1 A/N/E] (30ms, 137 bytes AUTH)
[3176   3]    DELEGATION RETRY without QNAME minimization
[3176   3]    SENDING udp4: @193.108.88.128 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 181 bytes AUTH)
[3207   2]   DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.": NOERROR with 9 servers
[3207   2]   QUERY A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." from 9 servers
[3207   3]    SENDING udp4: @193.108.88.128 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (32ms, 181 bytes AUTH)
[3239   3]    CNAME @193.108.88.128 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => "e13678.dscb.akamaiedge.net."
[3239   3]    DELEGATION QUERY "e13678.dscb.akamaiedge.net."
[3239   4]     CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[3239   4]     SENDING udp4: @192.43.172.30 NS "akamaiedge.net." => NOERROR [0+8+10 A/N/E] (12ms, 771 bytes)
[3251   4]     SENDING udp4: @95.100.173.192 NS "dscb.akamaiedge.net." => NOERROR [0+8+11 A/N/E] (29ms, 838 bytes)
[3280   4]     SENDING udp4: @88.221.81.192 NS "e13678.dscb.akamaiedge.net." => NOERROR [0+1+1 A/N/E] (41ms, 152 bytes AUTH)
[3321   3]    DELEGATION ANSWER "e13678.dscb.akamaiedge.net.": NOERROR with 8 servers
[3321   3]    QUERY A "e13678.dscb.akamaiedge.net." from 8 servers
[3321   4]     SENDING udp4: @88.221.81.192 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (39ms, 97 bytes AUTH)
[3360   3]    ANSWER @88.221.81.192 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (97 bytes AUTH)
[3360   2]   ANSWER @88.221.81.192 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [2+0+1 A/N/E] (223 bytes)
[3360   1]  ANSWER @88.221.81.192 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [3+0+1 A/N/E] (303 bytes)
[3360   0] ANSWER @88.221.81.192 A "www.microsoft.com." => NOERROR [4+0+1 A/N/E] (351 bytes)

;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @88.221.81.192 A www.microsoft.com
;; opcode: QUERY, status: NOERROR, id: 54903
;; flags: qr; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;www.microsoft.com.     IN       A

;; ANSWER SECTION:
www.microsoft.com.      3600    IN      CNAME   www.microsoft.com-c-3.edgekey.net.
www.microsoft.com-c-3.edgekey.net.      900     IN      CNAME   www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.
www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.       900     IN      CNAME   e13678.dscb.akamaiedge.net.
e13678.dscb.akamaiedge.net.     20      IN      A       23.12.158.97

;; GZPACK: H4sIAAAAAAAA/7pW3sDAwMjAwsDAwMhcXl7OmZuZXJRfnJ9WwpycnwuSwirMysDIwMAnwKCMKsmenJ+rm6xrzJ6akp6anVrJnJdawkCEEoh5zC0MVoQVc6fn5Ccl5hSlpmQWsSVmJ6bkFRNpDS6dcNtl2FINjc3MLVhSipOTuBKzE3MTM0H6warwyYGCiYGBQYSBRZxnXiIDg6YAAwQAAgAA///i1JItXwEAAA==
;; SERVER: 88.221.81.192
;; CACHE: size 24, hit ratio 21.28%
```
