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
[0      1]  SENDING udp4: @198.41.0.4 NS "com." => NOERROR [0+13+27 A/N/E] (11ms, 1527 bytes)
[12     1]  SENDING udp4: @192.5.6.30 NS "microsoft.com." => NOERROR [0+4+2 A/N/E] (129ms, 267 bytes)
[141    1]  GLUE QUERY [ns2-39.azure-dns.net. ns3-39.azure-dns.org. ns4-39.azure-dns.info.]
[141    2]   DELEGATION QUERY "ns2-39.azure-dns.net."
[141    3]    SENDING udp4: @198.41.0.4 NS "net." => NOERROR [0+13+27 A/N/E] (10ms, 1527 bytes)
[152    3]    SENDING udp4: @192.12.94.30 NS "azure-dns.net." => NOERROR [0+4+9 A/N/E] (133ms, 566 bytes)
[285    3]    SENDING udp4: @150.171.21.3 NS "ns2-39.azure-dns.net." => NOERROR [0+1+1 A/N/E] (6ms, 151 bytes AUTH)
[292    2]   DELEGATION ANSWER "ns2-39.azure-dns.net.": NOERROR with 4 servers
[292    2]   QUERY A "ns2-39.azure-dns.net." from 4 servers
[292    3]    SENDING udp4: @150.171.21.3 A "ns2-39.azure-dns.net." => NOERROR [1+0+1 A/N/E] (26ms, 85 bytes AUTH)
[318    2]   ANSWER @150.171.21.3 A "ns2-39.azure-dns.net." => NOERROR [1+0+1 A/N/E] (85 bytes AUTH)
[318    2]   DELEGATION QUERY "ns3-39.azure-dns.org."
[318    3]    SENDING udp4: @198.41.0.4 NS "org." => NOERROR [0+6+13 A/N/E] (10ms, 803 bytes)
[327    3]    SENDING udp4: @199.19.57.1 NS "azure-dns.org." => NOERROR [0+4+9 A/N/E] (202ms, 566 bytes)
[530    3]    SENDING udp4: @204.14.183.3 NS "ns3-39.azure-dns.org." => NOERROR [0+1+1 A/N/E] (6ms, 151 bytes AUTH)
[536    2]   DELEGATION ANSWER "ns3-39.azure-dns.org.": NOERROR with 4 servers
[536    2]   QUERY A "ns3-39.azure-dns.org." from 4 servers
[536    3]    SENDING udp4: @204.14.183.3 A "ns3-39.azure-dns.org." => NOERROR [1+0+1 A/N/E] (8ms, 85 bytes AUTH)
[545    2]   ANSWER @204.14.183.3 A "ns3-39.azure-dns.org." => NOERROR [1+0+1 A/N/E] (85 bytes AUTH)
[545    2]   DELEGATION QUERY "ns4-39.azure-dns.info."
[545    3]    SENDING udp4: @198.41.0.4 NS "info." => NOERROR [0+6+13 A/N/E] (11ms, 828 bytes)
[556    3]    SENDING udp4: @199.249.121.1 NS "azure-dns.info." => NOERROR [0+4+9 A/N/E] (10ms, 583 bytes)
[566    3]    SENDING udp4: @208.84.5.3 NS "ns4-39.azure-dns.info." => NOERROR [0+1+1 A/N/E] (22ms, 153 bytes AUTH)
[588    2]   DELEGATION ANSWER "ns4-39.azure-dns.info.": NOERROR with 4 servers
[588    2]   QUERY A "ns4-39.azure-dns.info." from 4 servers
[588    3]    SENDING udp4: @208.84.5.3 A "ns4-39.azure-dns.info." => NOERROR [1+0+1 A/N/E] (15ms, 87 bytes AUTH)
[603    2]   ANSWER @208.84.5.3 A "ns4-39.azure-dns.info." => NOERROR [1+0+1 A/N/E] (87 bytes AUTH)
[603    1]  GLUE ANSWER [150.171.16.39 13.107.222.39 13.107.206.39]
[603    1]  SENDING udp4: @13.107.222.39 NS "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (8ms, 110 bytes AUTH)
[612    0] DELEGATION ANSWER "www.microsoft.com.": NOERROR with 4 servers
[612    0] QUERY A "www.microsoft.com." from 4 servers
[612    1]  SENDING udp4: @13.107.222.39 A "www.microsoft.com." => NOERROR [1+0+1 A/N/E] (8ms, 110 bytes AUTH)
[620    1]  CNAME @13.107.222.39 A "www.microsoft.com." => "www.microsoft.com-c-3.edgekey.net."
[620    1]  DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net."
[620    2]   CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[620    2]   SENDING udp4: @192.26.92.30 NS "edgekey.net." => NOERROR [0+8+17 A/N/E] (134ms, 943 bytes)
[754    2]   SENDING udp4: @184.26.160.65 NS "com-c-3.edgekey.net." => NOERROR [0+1+1 A/N/E] (36ms, 132 bytes AUTH)
[790    2]   DELEGATION RETRY without QNAME minimization
[790    2]   SENDING udp4: @184.26.160.65 NS "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (27ms, 165 bytes AUTH)
[817    2]   SENDING udp4: @184.26.160.65 NS "microsoft.com-c-3.edgekey.net." => NOERROR [0+1+1 A/N/E] (27ms, 142 bytes AUTH)
[844    2]   DELEGATION RETRY without QNAME minimization
[844    2]   SENDING udp4: @184.26.160.65 NS "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (29ms, 165 bytes AUTH)
[872    2]   SENDING udp4: @184.26.160.65 NS "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (28ms, 165 bytes AUTH)
[901    1]  DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.": NOERROR with 8 servers
[901    1]  QUERY A "www.microsoft.com-c-3.edgekey.net." from 8 servers
[901    2]   SENDING udp4: @184.26.160.65 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [1+0+1 A/N/E] (26ms, 165 bytes AUTH)
[927    2]   CNAME @184.26.160.65 A "www.microsoft.com-c-3.edgekey.net." => "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net."
[927    2]   DELEGATION QUERY "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net."
[927    3]    CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[927    3]    SENDING udp4: @192.41.162.30 NS "akadns.net." => NOERROR [0+9+11 A/N/E] (38ms, 807 bytes)
[965    3]    GLUE QUERY [a28-129.akagtm.org. a18-128.akagtm.org. a42-130.akagtm.org. a7-130.akagtm.org.]
[965    4]     DELEGATION QUERY "a28-129.akagtm.org."
[965    5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[965    5]      SENDING udp4: @199.19.56.1 NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (201ms, 717 bytes)
[1166   5]      SENDING udp4: @23.61.245.128 NS "a28-129.akagtm.org." => NOERROR [0+1+1 A/N/E] (32ms, 131 bytes AUTH)
[1199   4]     DELEGATION ANSWER "a28-129.akagtm.org.": NOERROR with 9 servers
[1199   4]     QUERY A "a28-129.akagtm.org." from 9 servers
[1199   5]      SENDING udp4: @23.61.245.128 A "a28-129.akagtm.org." => NOERROR [1+0+1 A/N/E] (31ms, 81 bytes AUTH)
[1230   4]     ANSWER @23.61.245.128 A "a28-129.akagtm.org." => NOERROR [1+0+1 A/N/E] (81 bytes AUTH)
[1230   4]     DELEGATION QUERY "a18-128.akagtm.org."
[1230   5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[1230   5]      CACHED: NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (717 bytes)
[1230   5]      SENDING udp4: @95.100.168.128 NS "a18-128.akagtm.org." => NOERROR [0+1+1 A/N/E] (31ms, 131 bytes AUTH)
[1261   4]     DELEGATION ANSWER "a18-128.akagtm.org.": NOERROR with 9 servers
[1261   4]     QUERY A "a18-128.akagtm.org." from 9 servers
[1261   5]      SENDING udp4: @95.100.168.128 A "a18-128.akagtm.org." => NOERROR [1+0+1 A/N/E] (32ms, 81 bytes AUTH)
[1293   4]     ANSWER @95.100.168.128 A "a18-128.akagtm.org." => NOERROR [1+0+1 A/N/E] (81 bytes AUTH)
[1293   4]     DELEGATION QUERY "a42-130.akagtm.org."
[1293   5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[1293   5]      CACHED: NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (717 bytes)
[1293   5]      SENDING udp4: @2.17.46.130 NS "a42-130.akagtm.org." => NOERROR [0+1+1 A/N/E] (36ms, 131 bytes AUTH)
[1329   4]     DELEGATION ANSWER "a42-130.akagtm.org.": NOERROR with 9 servers
[1329   4]     QUERY A "a42-130.akagtm.org." from 9 servers
[1329   5]      SENDING udp4: @2.17.46.130 A "a42-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (30ms, 81 bytes AUTH)
[1359   4]     ANSWER @2.17.46.130 A "a42-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (81 bytes AUTH)
[1359   4]     DELEGATION QUERY "a7-130.akagtm.org."
[1359   5]      CACHED: NS "org." => NOERROR [0+6+13 A/N/E] (803 bytes)
[1359   5]      CACHED: NS "akagtm.org." => NOERROR [0+9+10 A/N/E] (717 bytes)
[1359   5]      SENDING udp4: @95.101.36.130 NS "a7-130.akagtm.org." => NOERROR [0+1+1 A/N/E] (32ms, 130 bytes AUTH)
[1391   4]     DELEGATION ANSWER "a7-130.akagtm.org.": NOERROR with 9 servers
[1392   4]     QUERY A "a7-130.akagtm.org." from 9 servers
[1392   5]      SENDING udp4: @95.101.36.130 A "a7-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (30ms, 79 bytes AUTH)
[1426   4]     ANSWER @95.101.36.130 A "a7-130.akagtm.org." => NOERROR [1+0+1 A/N/E] (79 bytes AUTH)
[1426   3]    GLUE ANSWER [95.100.173.129 95.101.36.128 184.28.92.130 23.61.199.130]
[1426   3]    SENDING udp4: @23.61.199.130 NS "globalredir.akadns.net." => NOERROR [0+1+1 A/N/E] (31ms, 137 bytes AUTH)
[1457   3]    DELEGATION RETRY without QNAME minimization
[1457   3]    SENDING udp4: @23.61.199.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (32ms, 181 bytes AUTH)
[1489   3]    SENDING udp4: @23.61.199.130 NS "net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 111 bytes AUTH)
[1520   3]    DELEGATION RETRY without QNAME minimization
[1520   3]    SENDING udp4: @23.61.199.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (34ms, 181 bytes AUTH)
[1555   3]    SENDING udp4: @23.61.199.130 NS "edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 127 bytes AUTH)
[1586   3]    DELEGATION RETRY without QNAME minimization
[1586   3]    SENDING udp4: @23.61.199.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (35ms, 181 bytes AUTH)
[1622   3]    SENDING udp4: @23.61.199.130 NS "com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 143 bytes AUTH)
[1653   3]    DELEGATION RETRY without QNAME minimization
[1653   3]    SENDING udp4: @23.61.199.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (31ms, 181 bytes AUTH)
[1684   3]    SENDING udp4: @23.61.199.130 NS "microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (32ms, 163 bytes AUTH)
[1716   3]    DELEGATION RETRY without QNAME minimization
[1716   3]    SENDING udp4: @23.61.199.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (32ms, 181 bytes AUTH)
[1748   3]    SENDING udp4: @23.61.199.130 NS "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (29ms, 181 bytes AUTH)
[1777   2]   DELEGATION ANSWER "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.": NOERROR with 9 servers
[1777   2]   QUERY A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." from 9 servers
[1777   3]    SENDING udp4: @23.61.199.130 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [1+0+1 A/N/E] (30ms, 181 bytes AUTH)
[1808   3]    CNAME @23.61.199.130 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => "e13678.dscb.akamaiedge.net."
[1808   3]    DELEGATION QUERY "e13678.dscb.akamaiedge.net."
[1808   4]     CACHED: NS "net." => NOERROR [0+13+27 A/N/E] (1527 bytes)
[1808   4]     SENDING udp4: @192.35.51.30 NS "akamaiedge.net." => NOERROR [0+8+10 A/N/E] (11ms, 771 bytes)
[1818   4]     SENDING udp4: @23.211.133.192 NS "dscb.akamaiedge.net." => NOERROR [0+8+11 A/N/E] (29ms, 838 bytes)
[1848   4]     SENDING udp4: @23.3.91.145 NS "e13678.dscb.akamaiedge.net." => NOERROR [0+1+1 A/N/E] (11ms, 152 bytes AUTH)
[1859   3]    DELEGATION ANSWER "e13678.dscb.akamaiedge.net.": NOERROR with 8 servers
[1859   3]    QUERY A "e13678.dscb.akamaiedge.net." from 8 servers
[1859   4]     SENDING udp4: @23.3.91.145 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (10ms, 97 bytes AUTH)
[1869   3]    ANSWER @23.3.91.145 A "e13678.dscb.akamaiedge.net." => NOERROR [1+0+1 A/N/E] (97 bytes AUTH)
[1869   2]   ANSWER @23.3.91.145 A "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net." => NOERROR [2+0+1 A/N/E] (223 bytes AUTH)
[1869   1]  ANSWER @23.3.91.145 A "www.microsoft.com-c-3.edgekey.net." => NOERROR [3+0+1 A/N/E] (303 bytes AUTH)
[1869   0] ANSWER @23.3.91.145 A "www.microsoft.com." => NOERROR [4+0+1 A/N/E] (351 bytes AUTH)

;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @23.3.91.145 A www.microsoft.com
;; opcode: QUERY, status: NOERROR, id: 48643
;; flags: qr aa; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;www.microsoft.com.     IN       A

;; ANSWER SECTION:
www.microsoft.com.      3600    IN      CNAME   www.microsoft.com-c-3.edgekey.net.
www.microsoft.com-c-3.edgekey.net.      900     IN      CNAME   www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.
www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.       900     IN      CNAME   e13678.dscb.akamaiedge.net.
e13678.dscb.akamaiedge.net.     20      IN      A       23.12.158.97

;; GZPACK: H4sIAAAAAAAA/9rH3MLAwMjAwsDAwMhcXl7OmZuZXJRfnJ9WwpycnwuSwirMysDIwMAnwKCMKsmenJ+rm6xrzJ6akp6anVrJnJdawkCEEoh5zC0MVoQVc6fn5Ccl5hSlpmQWsSVmJ6bkFRNpDS6dcNtl2FINjc3MLVhSipOTuBKzE3MTM0H6warwyYGCiYGBQYSBRZxnXiIDg6YAAwQAAgAA//+PeYezXwEAAA==
;; SERVER: 23.3.91.145
;; CACHE: size 24, hit ratio 16.95%
```
