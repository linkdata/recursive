package main

import (
	"context"
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

	"github.com/linkdata/recursive"
	"github.com/miekg/dns"
)

var flagCpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var flagMemprofile = flag.String("memprofile", "", "write memory profile to `file`")
var flagCount = flag.Int("count", 1, "repeat count")
var flagSleep = flag.Int("sleep", 0, "sleep ms between repeats")
var flag4 = flag.Bool("4", true, "use IPv4")
var flag6 = flag.Bool("6", false, "use IPv6")
var debug = flag.Bool("debug", false, "print debug output")

func main() {
	flag.Parse()
	if *flagCpuprofile != "" {
		f, err := os.Create(*flagCpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
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

	rec := recursive.NewWithOptions(roots4, roots6)
	rec.OrderRoots(context.Background(), nil)

	var dbgout io.Writer
	if *debug {
		dbgout = os.Stderr
	}

	for i := 0; i < *flagCount; i++ {
		if i > 0 && *flagSleep > 0 {
			time.Sleep(time.Millisecond * time.Duration(*flagSleep))
		}
		for _, qname := range qnames {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			if retv, _, err := rec.ResolveWithOptions(ctx, nil, recursive.DefaultCache, dbgout, qname, qtype); err == nil {
				if !*debug {
					fmt.Println(retv)
				}
			} else {
				fmt.Printf("%s %s: %v\n", recursive.DnsTypeToString(qtype), qname, err)
			}
			cancel()
		}
	}

	fmt.Printf("cache size %d, hit ratio %.2f%%\n", recursive.DefaultCache.Entries(), recursive.DefaultCache.HitRatio())

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
