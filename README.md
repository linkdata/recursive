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
to normal resolution. For example, here is the output with debug logging for
`A console.aws.amazon.com`:

```
$ go run ./cmd/cli -debug A console.aws.amazon.com
[0      1]  QUERY NS "com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[0      1]  SENDING udp4: @198.41.0.4 NS "com." COOKIE:c="55d80081..." s="" => NOERROR [0+13+27 A/N/E] (3ms, 1527 bytes)
[3      1]  QUERY NS "amazon.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[3      1]  SENDING udp4: @192.5.6.30 NS "amazon.com." COOKIE:c="55d80081..." s="" => NOERROR [0+8+5 A/N/E] (22ms, 503 bytes)
[26     1]  QUERY NS "aws.amazon.com." from [ns1.amzndns.com. 156.154.64.10 ns2.amzndns.com. 156.154.68.10 ns1.amzndns.net. ns1.amzndns.org.]
[26     1]  SENDING udp4: @156.154.64.10 NS "aws.amazon.com." COOKIE:c="55d80081..." s="" => NOERROR [1+4+1 A/N/E] (2ms, 359 bytes AUTH)
[29     1]  QUERY NS "console.aws.amazon.com." from [ns-1172.awsdns-18.org. ns-439.awsdns-54.com. ns-959.awsdns-55.net. ns-2017.awsdns-60.co.uk.]
[29     1]  GLUE lookup for NS "ns-1172.awsdns-18.org."
[29     2]   QUERY A "org." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[29     2]   SENDING udp4: @198.41.0.4 A "org." => NOERROR [0+6+13 A/N/E] (2ms, 803 bytes)
[30     2]   QUERY A "awsdns-18.org." from [c0.org.afilias-nst.info. 199.19.53.1 b0.org.afilias-nst.org. 199.19.54.1 a0.org.afilias-nst.info. 199.19.56.1 d0.org.afilias-nst.org. 199.19.57.1]
[30     2]   SENDING udp4: @199.19.53.1 A "awsdns-18.org." COOKIE:c="55d80081..." s="" => NOERROR [0+4+9 A/N/E] (255ms, 596 bytes)
[286    2]   QUERY A "ns-1172.awsdns-18.org." from [g-ns-146.awsdns-18.org. 205.251.192.146 g-ns-724.awsdns-18.org. 205.251.194.212 g-ns-1045.awsdns-18.org. 205.251.196.21 g-ns-1618.awsdns-18.org. 205.251.198.82]
[286    2]   SENDING udp4: @205.251.192.146 A "ns-1172.awsdns-18.org." COOKIE:c="55d80081..." s="" => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[289    2]   QUERY FINAL A "ns-1172.awsdns-18.org." from [g-ns-146.awsdns-18.org. 205.251.192.146 g-ns-724.awsdns-18.org. 205.251.194.212 g-ns-1045.awsdns-18.org. 205.251.196.21 g-ns-1618.awsdns-18.org. 205.251.198.82]
[290    2]   cached answer: A "ns-1172.awsdns-18.org." => NOERROR [1+4+9 A/N/E] AUTH
[290    2]   final nameservers: [205.251.192.146 205.251.194.212 205.251.196.21 205.251.198.82]
[290    2]   cached answer: A "ns-1172.awsdns-18.org." => NOERROR [1+4+9 A/N/E] AUTH
[290    2]   ANSWER NOERROR for A "ns-1172.awsdns-18.org." with 1 records
[290    1]  SENDING udp4: @205.251.196.148 NS "console.aws.amazon.com." COOKIE:c="55d80081..." s="" => REFUSED [0+0+0 A/N/E] (5ms, 40 bytes)
[295    1]  got REFUSED, retry without QNAME minimization
[295    2]   QUERY A "console.aws.amazon.com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[295    2]   SENDING udp4: @198.41.0.4 A "console.aws.amazon.com." => NOERROR [0+13+27 A/N/E] (2ms, 1546 bytes)
[298    2]   QUERY A "console.aws.amazon.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[298    2]   SENDING udp4: @192.5.6.30 A "console.aws.amazon.com." => NOERROR [0+8+5 A/N/E] (23ms, 515 bytes)
[321    2]   QUERY A "console.aws.amazon.com." from [ns1.amzndns.com. 156.154.64.10 ns2.amzndns.com. 156.154.68.10 ns1.amzndns.net. ns1.amzndns.org.]
[321    2]   SENDING udp4: @156.154.64.10 A "console.aws.amazon.com." => NOERROR [1+4+1 A/N/E] (2ms, 345 bytes AUTH)
[324    2]   CNAME QUERY "console.aws.amazon.com." => "console.cname-proxy.amazon.com."
[324    3]    QUERY A "console.cname-proxy.amazon.com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[324    3]    SENDING udp4: @198.41.0.4 A "console.cname-proxy.amazon.com." => NOERROR [0+13+27 A/N/E] (2ms, 1554 bytes)
[326    3]    QUERY A "console.cname-proxy.amazon.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[326    3]    SENDING udp4: @192.5.6.30 A "console.cname-proxy.amazon.com." => NOERROR [0+8+5 A/N/E] (24ms, 523 bytes)
[350    3]    QUERY A "console.cname-proxy.amazon.com." from [ns1.amzndns.com. 156.154.64.10 ns2.amzndns.com. 156.154.68.10 ns1.amzndns.net. ns1.amzndns.org.]
[350    3]    SENDING udp4: @156.154.64.10 A "console.cname-proxy.amazon.com." => NOERROR [0+4+1 A/N/E] (2ms, 287 bytes)
[353    3]    QUERY A "console.cname-proxy.amazon.com." from [ns-1313.awsdns-36.org. ns-429.awsdns-53.com. ns-689.awsdns-22.net. ns-1878.awsdns-42.co.uk.]
[353    3]    GLUE lookup for NS "ns-1313.awsdns-36.org."
[353    4]     QUERY A "ns-1313.awsdns-36.org." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[353    4]     SENDING udp4: @198.41.0.4 A "ns-1313.awsdns-36.org." => NOERROR [0+6+13 A/N/E] (2ms, 821 bytes)
[354    4]     QUERY A "ns-1313.awsdns-36.org." from [c0.org.afilias-nst.info. 199.19.53.1 b0.org.afilias-nst.org. 199.19.54.1 a0.org.afilias-nst.info. 199.19.56.1 d0.org.afilias-nst.org. 199.19.57.1]
[354    4]     SENDING udp4: @199.19.53.1 A "ns-1313.awsdns-36.org." => NOERROR [0+4+9 A/N/E] (261ms, 604 bytes)
[615    4]     QUERY A "ns-1313.awsdns-36.org." from [g-ns-164.awsdns-36.org. 205.251.192.164 g-ns-742.awsdns-36.org. 205.251.194.230 g-ns-1063.awsdns-36.org. 205.251.196.39 g-ns-1636.awsdns-36.org. 205.251.198.100]
[615    4]     SENDING udp4: @205.251.192.164 A "ns-1313.awsdns-36.org." COOKIE:c="55d80081..." s="" => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[618    4]     QUERY FINAL A "ns-1313.awsdns-36.org." from [g-ns-164.awsdns-36.org. 205.251.192.164 g-ns-742.awsdns-36.org. 205.251.194.230 g-ns-1063.awsdns-36.org. 205.251.196.39 g-ns-1636.awsdns-36.org. 205.251.198.100]
[618    4]     SENDING udp4: @205.251.192.164 A "ns-1313.awsdns-36.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[620    4]     final nameservers: [205.251.192.164 205.251.194.230 205.251.196.39 205.251.198.100]
[620    4]     SENDING udp4: @205.251.192.164 A "ns-1313.awsdns-36.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[623    4]     ANSWER NOERROR for A "ns-1313.awsdns-36.org." with 1 records
[623    3]    SENDING udp4: @205.251.197.33 A "console.cname-proxy.amazon.com." COOKIE:c="55d80081..." s="" => NOERROR [1+4+1 A/N/E] (5ms, 359 bytes AUTH)
[628    3]    CNAME QUERY "console.cname-proxy.amazon.com." => "lbr.us.console.amazonaws.com."
[628    4]     QUERY A "lbr.us.console.amazonaws.com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[628    4]     SENDING udp4: @198.41.0.4 A "lbr.us.console.amazonaws.com." => NOERROR [0+13+27 A/N/E] (2ms, 1552 bytes)
[630    4]     QUERY A "lbr.us.console.amazonaws.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[630    4]     SENDING udp4: @192.5.6.30 A "lbr.us.console.amazonaws.com." => NOERROR [0+4+2 A/N/E] (23ms, 283 bytes)
[653    4]     QUERY A "lbr.us.console.amazonaws.com." from [ns-27.awsdns-03.com. 205.251.192.27 ns-1321.awsdns-37.org. ns-967.awsdns-56.net. ns-1670.awsdns-16.co.uk.]
[653    4]     SENDING udp4: @205.251.192.27 A "lbr.us.console.amazonaws.com." COOKIE:c="55d80081..." s="" => NOERROR [0+4+1 A/N/E] (2ms, 281 bytes)
[656    4]     QUERY A "lbr.us.console.amazonaws.com." from [ns-1342.awsdns-39.org. ns-372.awsdns-46.com. ns-671.awsdns-19.net. ns-1832.awsdns-37.co.uk.]
[656    4]     GLUE lookup for NS "ns-1342.awsdns-39.org."
[656    5]      QUERY A "ns-1342.awsdns-39.org." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[656    5]      SENDING udp4: @198.41.0.4 A "ns-1342.awsdns-39.org." => NOERROR [0+6+13 A/N/E] (1ms, 821 bytes)
[657    5]      QUERY A "ns-1342.awsdns-39.org." from [c0.org.afilias-nst.info. 199.19.53.1 b0.org.afilias-nst.org. 199.19.54.1 a0.org.afilias-nst.info. 199.19.56.1 d0.org.afilias-nst.org. 199.19.57.1]
[657    5]      SENDING udp4: @199.19.53.1 A "ns-1342.awsdns-39.org." => NOERROR [0+4+9 A/N/E] (268ms, 604 bytes)
[925    5]      QUERY A "ns-1342.awsdns-39.org." from [g-ns-167.awsdns-39.org. 205.251.192.167 g-ns-745.awsdns-39.org. 205.251.194.233 g-ns-1066.awsdns-39.org. 205.251.196.42 g-ns-1639.awsdns-39.org. 205.251.198.103]
[926    5]      SENDING udp4: @205.251.192.167 A "ns-1342.awsdns-39.org." COOKIE:c="55d80081..." s="" => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[928    5]      QUERY FINAL A "ns-1342.awsdns-39.org." from [g-ns-167.awsdns-39.org. 205.251.192.167 g-ns-745.awsdns-39.org. 205.251.194.233 g-ns-1066.awsdns-39.org. 205.251.196.42 g-ns-1639.awsdns-39.org. 205.251.198.103]
[928    5]      SENDING udp4: @205.251.192.167 A "ns-1342.awsdns-39.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[931    5]      final nameservers: [205.251.192.167 205.251.194.233 205.251.196.42 205.251.198.103]
[931    5]      SENDING udp4: @205.251.192.167 A "ns-1342.awsdns-39.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[934    5]      ANSWER NOERROR for A "ns-1342.awsdns-39.org." with 1 records
[934    4]     SENDING udp4: @205.251.197.62 A "lbr.us.console.amazonaws.com." COOKIE:c="55d80081..." s="" => NOERROR [0+4+1 A/N/E] (4ms, 293 bytes)
[939    4]     QUERY A "lbr.us.console.amazonaws.com." from [ns-1335.awsdns-38.org. ns-499.awsdns-62.com. ns-611.awsdns-12.net. ns-1892.awsdns-44.co.uk.]
[939    4]     GLUE lookup for NS "ns-1335.awsdns-38.org."
[939    5]      QUERY A "ns-1335.awsdns-38.org." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[939    5]      SENDING udp4: @198.41.0.4 A "ns-1335.awsdns-38.org." => NOERROR [0+6+13 A/N/E] (2ms, 821 bytes)
[941    5]      QUERY A "ns-1335.awsdns-38.org." from [c0.org.afilias-nst.info. 199.19.53.1 b0.org.afilias-nst.org. 199.19.54.1 a0.org.afilias-nst.info. 199.19.56.1 d0.org.afilias-nst.org. 199.19.57.1]
[941    5]      SENDING udp4: @199.19.53.1 A "ns-1335.awsdns-38.org." => NOERROR [0+4+9 A/N/E] (265ms, 604 bytes)
[1206   5]      QUERY A "ns-1335.awsdns-38.org." from [g-ns-166.awsdns-38.org. 205.251.192.166 g-ns-744.awsdns-38.org. 205.251.194.232 g-ns-1065.awsdns-38.org. 205.251.196.41 g-ns-1638.awsdns-38.org. 205.251.198.102]
[1206   5]      SENDING udp4: @205.251.192.166 A "ns-1335.awsdns-38.org." COOKIE:c="55d80081..." s="" => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[1209   5]      QUERY FINAL A "ns-1335.awsdns-38.org." from [g-ns-166.awsdns-38.org. 205.251.192.166 g-ns-744.awsdns-38.org. 205.251.194.232 g-ns-1065.awsdns-38.org. 205.251.196.41 g-ns-1638.awsdns-38.org. 205.251.198.102]
[1209   5]      SENDING udp4: @205.251.192.166 A "ns-1335.awsdns-38.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[1212   5]      final nameservers: [205.251.192.166 205.251.194.232 205.251.196.41 205.251.198.102]
[1212   5]      SENDING udp4: @205.251.192.166 A "ns-1335.awsdns-38.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[1215   5]      ANSWER NOERROR for A "ns-1335.awsdns-38.org." with 1 records
[1215   4]     SENDING udp4: @205.251.197.55 A "lbr.us.console.amazonaws.com." COOKIE:c="55d80081..." s="" => NOERROR [1+4+1 A/N/E] (5ms, 368 bytes AUTH)
[1220   4]     CNAME QUERY "lbr.us.console.amazonaws.com." => "eu-north-1.console.aws.amazon.com."
[1220   5]      QUERY A "eu-north-1.console.aws.amazon.com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[1220   5]      SENDING udp4: @198.41.0.4 A "eu-north-1.console.aws.amazon.com." => NOERROR [0+13+27 A/N/E] (2ms, 1557 bytes)
[1223   5]      QUERY A "eu-north-1.console.aws.amazon.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[1223   5]      SENDING udp4: @192.5.6.30 A "eu-north-1.console.aws.amazon.com." => NOERROR [0+8+5 A/N/E] (23ms, 526 bytes)
[1246   5]      QUERY A "eu-north-1.console.aws.amazon.com." from [ns1.amzndns.com. 156.154.64.10 ns2.amzndns.com. 156.154.68.10 ns1.amzndns.net. ns1.amzndns.org.]
[1246   5]      SENDING udp4: @156.154.64.10 A "eu-north-1.console.aws.amazon.com." => NOERROR [1+4+1 A/N/E] (3ms, 378 bytes AUTH)
[1249   5]      CNAME QUERY "eu-north-1.console.aws.amazon.com." => "eu-north-1.console.cname-proxy.amazon.com."
[1249   6]       QUERY A "eu-north-1.console.cname-proxy.amazon.com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[1249   6]       SENDING udp4: @198.41.0.4 A "eu-north-1.console.cname-proxy.amazon.com." => NOERROR [0+13+27 A/N/E] (2ms, 1565 bytes)
[1251   6]       QUERY A "eu-north-1.console.cname-proxy.amazon.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[1251   6]       SENDING udp4: @192.5.6.30 A "eu-north-1.console.cname-proxy.amazon.com." => NOERROR [0+8+5 A/N/E] (21ms, 534 bytes)
[1273   6]       QUERY A "eu-north-1.console.cname-proxy.amazon.com." from [ns1.amzndns.com. 156.154.64.10 ns2.amzndns.com. 156.154.68.10 ns1.amzndns.net. ns1.amzndns.org.]
[1273   6]       SENDING udp4: @156.154.64.10 A "eu-north-1.console.cname-proxy.amazon.com." => NOERROR [0+4+1 A/N/E] (2ms, 298 bytes)
[1275   6]       QUERY A "eu-north-1.console.cname-proxy.amazon.com." from [ns-1313.awsdns-36.org. 205.251.197.33 ns-429.awsdns-53.com. ns-689.awsdns-22.net. ns-1878.awsdns-42.co.uk.]
[1275   6]       SENDING udp4: @205.251.197.33 A "eu-north-1.console.cname-proxy.amazon.com." => NOERROR [1+4+1 A/N/E] (4ms, 396 bytes AUTH)
[1279   6]       CNAME QUERY "eu-north-1.console.cname-proxy.amazon.com." => "gr.aga.console-geo.eu-north-1.amazonaws.com."
[1279   7]        QUERY A "gr.aga.console-geo.eu-north-1.amazonaws.com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[1279   7]        SENDING udp4: @198.41.0.4 A "gr.aga.console-geo.eu-north-1.amazonaws.com." => NOERROR [0+13+27 A/N/E] (3ms, 1567 bytes)
[1282   7]        QUERY A "gr.aga.console-geo.eu-north-1.amazonaws.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[1282   7]        SENDING udp4: @192.5.6.30 A "gr.aga.console-geo.eu-north-1.amazonaws.com." => NOERROR [0+4+2 A/N/E] (23ms, 298 bytes)
[1305   7]        QUERY A "gr.aga.console-geo.eu-north-1.amazonaws.com." from [ns-27.awsdns-03.com. 205.251.192.27 ns-1321.awsdns-37.org. ns-967.awsdns-56.net. ns-1670.awsdns-16.co.uk.]
[1305   7]        SENDING udp4: @205.251.192.27 A "gr.aga.console-geo.eu-north-1.amazonaws.com." => NOERROR [0+8+1 A/N/E] (2ms, 500 bytes)
[1307   7]        QUERY A "gr.aga.console-geo.eu-north-1.amazonaws.com." from [ns1.amzndns.com. 156.154.64.10 ns2.amzndns.com. 156.154.68.10 ns1.amzndns.net. ns1.amzndns.org.]
[1307   7]        SENDING udp4: @156.154.64.10 A "gr.aga.console-geo.eu-north-1.amazonaws.com." => NOERROR [0+4+1 A/N/E] (2ms, 356 bytes)
[1309   7]        QUERY A "gr.aga.console-geo.eu-north-1.amazonaws.com." from [ns-1055.awsdns-03.org. ns-148.awsdns-18.com. ns-581.awsdns-08.net. ns-1737.awsdns-25.co.uk.]
[1309   7]        GLUE lookup for NS "ns-1055.awsdns-03.org."
[1309   8]         QUERY A "ns-1055.awsdns-03.org." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[1309   8]         SENDING udp4: @198.41.0.4 A "ns-1055.awsdns-03.org." => NOERROR [0+6+13 A/N/E] (2ms, 821 bytes)
[1311   8]         QUERY A "ns-1055.awsdns-03.org." from [c0.org.afilias-nst.info. 199.19.53.1 b0.org.afilias-nst.org. 199.19.54.1 a0.org.afilias-nst.info. 199.19.56.1 d0.org.afilias-nst.org. 199.19.57.1]
[1311   8]         SENDING udp4: @199.19.53.1 A "ns-1055.awsdns-03.org." => NOERROR [0+4+9 A/N/E] (257ms, 604 bytes)
[1569   8]         QUERY A "ns-1055.awsdns-03.org." from [g-ns-131.awsdns-03.org. 205.251.192.131 g-ns-709.awsdns-03.org. 205.251.194.197 g-ns-1030.awsdns-03.org. 205.251.196.6 g-ns-1603.awsdns-03.org. 205.251.198.67]
[1569   8]         SENDING udp4: @205.251.192.131 A "ns-1055.awsdns-03.org." COOKIE:c="55d80081..." s="" => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[1571   8]         QUERY FINAL A "ns-1055.awsdns-03.org." from [g-ns-131.awsdns-03.org. 205.251.192.131 g-ns-709.awsdns-03.org. 205.251.194.197 g-ns-1030.awsdns-03.org. 205.251.196.6 g-ns-1603.awsdns-03.org. 205.251.198.67]
[1571   8]         SENDING udp4: @205.251.192.131 A "ns-1055.awsdns-03.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[1573   8]         final nameservers: [205.251.192.131 205.251.194.197 205.251.196.6 205.251.198.67]
[1573   8]         SENDING udp4: @205.251.192.131 A "ns-1055.awsdns-03.org." => NOERROR [1+4+9 A/N/E] (2ms, 641 bytes AUTH)
[1575   8]         ANSWER NOERROR for A "ns-1055.awsdns-03.org." with 1 records
[1575   7]        SENDING udp4: @205.251.196.31 A "gr.aga.console-geo.eu-north-1.amazonaws.com." COOKIE:c="55d80081..." s="" => NOERROR [1+4+1 A/N/E] (4ms, 455 bytes AUTH)
[1579   7]        CNAME QUERY "gr.aga.console-geo.eu-north-1.amazonaws.com." => "aba8735d2c3d241de.awsglobalaccelerator.com."
[1579   8]         QUERY A "aba8735d2c3d241de.awsglobalaccelerator.com." from [root 198.41.0.4 root 192.36.148.17 root 192.203.230.10 root 192.5.5.241]
[1579   8]         SENDING udp4: @198.41.0.4 A "aba8735d2c3d241de.awsglobalaccelerator.com." => NOERROR [0+13+27 A/N/E] (2ms, 1566 bytes)
[1581   8]         QUERY A "aba8735d2c3d241de.awsglobalaccelerator.com." from [a.gtld-servers.net. 192.5.6.30 e.gtld-servers.net. 192.12.94.30 c.gtld-servers.net. 192.26.92.30 d.gtld-servers.net. 192.31.80.30]
[1581   8]         SENDING udp4: @192.5.6.30 A "aba8735d2c3d241de.awsglobalaccelerator.com." => NOERROR [0+4+2 A/N/E] (23ms, 343 bytes)
[1605   8]         QUERY A "aba8735d2c3d241de.awsglobalaccelerator.com." from [ns-409.awsdns-51.com. 205.251.193.153 ns-1484.awsdns-57.org. ns-609.awsdns-12.net. ns-1949.awsdns-51.co.uk.]
[1605   8]         SENDING udp4: @205.251.193.153 A "aba8735d2c3d241de.awsglobalaccelerator.com." COOKIE:c="55d80081..." s="" => NOERROR [2+4+1 A/N/E] (2ms, 423 bytes AUTH)
[1607   8]         QUERY FINAL A "aba8735d2c3d241de.awsglobalaccelerator.com." from [ns-409.awsdns-51.com. 205.251.193.153 ns-1484.awsdns-57.org. ns-609.awsdns-12.net. ns-1949.awsdns-51.co.uk.]
[1607   8]         SENDING udp4: @205.251.193.153 A "aba8735d2c3d241de.awsglobalaccelerator.com." => NOERROR [2+4+1 A/N/E] (2ms, 423 bytes AUTH)
[1609   8]         final nameservers: [205.251.193.153]
[1609   8]         SENDING udp4: @205.251.193.153 A "aba8735d2c3d241de.awsglobalaccelerator.com." => NOERROR [2+4+1 A/N/E] (2ms, 423 bytes AUTH)
[1611   8]         ANSWER NOERROR for A "aba8735d2c3d241de.awsglobalaccelerator.com." with 2 records
[1611   7]        CNAME ANSWER NOERROR "aba8735d2c3d241de.awsglobalaccelerator.com." with 2 records
[1611   6]       CNAME ANSWER NOERROR "gr.aga.console-geo.eu-north-1.amazonaws.com." with 3 records
[1611   5]      CNAME ANSWER NOERROR "eu-north-1.console.cname-proxy.amazon.com." with 4 records
[1611   4]     CNAME ANSWER NOERROR "eu-north-1.console.aws.amazon.com." with 5 records
[1611   3]    CNAME ANSWER NOERROR "lbr.us.console.amazonaws.com." with 6 records
[1611   2]   CNAME ANSWER NOERROR "console.cname-proxy.amazon.com." with 7 records

;; opcode: QUERY, status: NOERROR, id: 39234
;; flags: qr aa rd; QUERY: 1, ANSWER: 8, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;console.aws.amazon.com.        IN       A

;; ANSWER SECTION:
console.aws.amazon.com. 7200    IN      CNAME   console.cname-proxy.amazon.com.
console.cname-proxy.amazon.com. 60      IN      CNAME   lbr.us.console.amazonaws.com.
lbr.us.console.amazonaws.com.   60      IN      CNAME   eu-north-1.console.aws.amazon.com.
eu-north-1.console.aws.amazon.com.      7200    IN      CNAME   eu-north-1.console.cname-proxy.amazon.com.
eu-north-1.console.cname-proxy.amazon.com.      60      IN      CNAME   gr.aga.console-geo.eu-north-1.amazonaws.com.
gr.aga.console-geo.eu-north-1.amazonaws.com.    60      IN      CNAME   aba8735d2c3d241de.awsglobalaccelerator.com.
aba8735d2c3d241de.awsglobalaccelerator.com.     300     IN      A       166.117.98.246
aba8735d2c3d241de.awsglobalaccelerator.com.     300     IN      A       166.117.166.206

;; AUTHORITY SECTION:
cname-proxy.amazon.com. 60      IN      NS      ns-1313.awsdns-36.org.
cname-proxy.amazon.com. 60      IN      NS      ns-1878.awsdns-42.co.uk.
cname-proxy.amazon.com. 60      IN      NS      ns-429.awsdns-53.com.
cname-proxy.amazon.com. 60      IN      NS      ns-689.awsdns-22.net.

;; Sent 56 queries in 1.611s
;; SERVER: 192.5.6.30
;;; cache size 3, hit ratio 20.00%
```
