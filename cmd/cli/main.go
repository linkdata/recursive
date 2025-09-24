package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/linkdata/rate"
	"github.com/linkdata/recursive"
	"github.com/miekg/dns"
)

var flagCpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var flagMemprofile = flag.String("memprofile", "", "write memory profile to `file`")
var flagTimeout = flag.Int("timeout", 60, "individual query timeout in seconds")
var flagMaxwait = flag.Int("maxwait", 60*1000, "max time to wait for result in milliseconds")
var flagRatelimit = flag.Int("ratelimit", 0, "rate limit queries, 0 means no limit")
var flagCount = flag.Int("count", 1, "repeat count")
var flagSleep = flag.Int("sleep", 0, "sleep ms between repeats")
var flag4 = flag.Bool("4", true, "use IPv4")
var flag6 = flag.Bool("6", false, "use IPv6")
var flagDebug = flag.Bool("debug", false, "print debug output")
var flagRecord = flag.Bool("record", false, "write a record of all queries made")

func recordFn(rec *recursive.Recursive, nsaddr netip.Addr, qtype uint16, qname string, m *dns.Msg, err error) {
	fmt.Println(";;; ----------------------------------------------------------------------")
	fmt.Printf("; <<>> recursive <<>> @%s %s %s\n", nsaddr, recursive.DnsTypeToString(qtype), qname)
	if m == nil && err != nil {
		m = new(dns.Msg)
		m.SetQuestion(qname, qtype)
		m.Rcode = dns.RcodeServerFailure
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetExtendedRcode(recursive.ExtendedErrorCodeFromError(err))
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{
			InfoCode:  recursive.ExtendedErrorCodeFromError(err),
			ExtraText: err.Error(),
		})
		m.Extra = append(m.Extra, opt)
		err = nil
	}
	if m != nil {
		fmt.Println(m)
		if b, e := m.Pack(); e == nil {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			if _, e = gw.Write(b); e == nil {
				if gw.Close() == nil {
					fmt.Printf(";; GZPACK: %s\n", base64.StdEncoding.EncodeToString(buf.Bytes()))
				}
			}
		}
		if err != nil {
			fmt.Printf(";; ERROR: %v\n", err)
		}
	}
	if nsaddr.IsValid() {
		fmt.Printf(";; SERVER: %s\n", nsaddr)
	}
}

func main() {
	flag.Parse()
	if *flagCpuprofile != "" {
		f, err := os.Create(*flagCpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		_ = pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	qtype := dns.TypeA
	qnames := []string{}
	for _, arg := range flag.Args() {
		if x, ok := dns.StringToType[strings.ToUpper(arg)]; ok {
			qtype = x
		} else {
			qnames = append(qnames, arg)
		}
	}

	if len(qnames) == 0 {
		fmt.Println("missing one or more names to query")
		return
	}

	var roots4, roots6 []netip.Addr
	if *flag4 {
		roots4 = recursive.Roots4
	}
	if *flag6 {
		roots6 = recursive.Roots6
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(*flagTimeout))
	defer cancel()

	maxrate := int32(*flagRatelimit) // #nosec G115
	var rateLimiter <-chan struct{}
	if maxrate > 0 {
		rateLimiter = rate.NewTicker(nil, &maxrate).C
	}

	rec := recursive.NewWithOptions(nil, recursive.DefaultCache, roots4, roots6, rateLimiter)
	rec.OrderRoots(ctx)

	if *flagRecord {
		rec.RecordFn = recordFn
	}

	var dbgout io.Writer
	if *flagDebug {
		dbgout = os.Stderr
	}

	for i := 0; i < *flagCount; i++ {
		if i > 0 && *flagSleep > 0 {
			time.Sleep(time.Millisecond * time.Duration(*flagSleep))
		}
		for _, qname := range qnames {
			ctx, cancel := context.WithTimeout(ctx, time.Millisecond*time.Duration(*flagMaxwait))
			retv, srv, err := rec.ResolveWithOptions(ctx, recursive.DefaultCache, dbgout, qname, qtype)
			if !*flagDebug && !*flagRecord {
				recordFn(rec, srv, qtype, qname, retv, err)
			}
			cancel()
		}
	}

	if !*flagRecord {
		fmt.Printf(";;; cache size %d, hit ratio %.2f%%\n", recursive.DefaultCache.Entries(), recursive.DefaultCache.HitRatio())
	}

	if *flagMemprofile != "" {
		f, err := os.Create(*flagMemprofile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}
