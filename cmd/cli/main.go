package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
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
	"github.com/linkdata/wgnet"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

func env(envname string) string {
	envval, _ := os.LookupEnv(envname)
	return os.ExpandEnv(envval)
}

var flagCpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var flagMemprofile = flag.String("memprofile", "", "write memory profile to `file`")
var flagTimeout = flag.Int("timeout", 60, "individual query timeout in seconds")
var flagMaxwait = flag.Int("maxwait", 60*1000, "max time to wait for result in milliseconds")
var flagCount = flag.Int("count", 1, "repeat count")
var flagSleep = flag.Int("sleep", 0, "sleep ms between repeats")
var flagDebug = flag.Bool("debug", false, "print debug output")
var flagRatelimit = flag.Int("ratelimit", 0, "rate limit queries, 0 means no limit")
var flag4 = flag.Bool("4", true, "use IPv4")
var flag6 = flag.Bool("6", false, "use IPv6")
var flagDeterministic = flag.Bool("deterministic", false, "do not randomize NS server order")
var flagWgConfig = flag.String("wgconfig", env("WGCONFIG"), "use WireGuard config file for outbound DNS queries")

var ErrOpenWireGuardConfig = errors.New("could not open WireGuard config file")
var ErrParseWireGuardConfig = errors.New("could not parse WireGuard config file")
var ErrOpenWireGuardDevice = errors.New("could not open WireGuard device")

func closeWithLog(name string, closer io.Closer) {
	if closer != nil {
		if err := closer.Close(); err != nil {
			log.Printf("close %s: %v", name, err)
		}
	}
}

func setResolverQueryTimeout(rec *recursive.Recursive, timeoutSeconds int) {
	if rec != nil {
		if timeoutSeconds > 0 {
			rec.Timeout = time.Second * time.Duration(timeoutSeconds)
		}
	}
}

func newWireGuardDialer(configPath string) (dialer proxy.ContextDialer, closer io.Closer, err error) {
	if configPath != "" {
		var file *os.File
		if file, err = os.Open(configPath); /* #nosec G304 */ err == nil {
			defer closeWithLog(configPath, file)
			var cfg *wgnet.Config
			if cfg, err = wgnet.Parse(file, nil); err == nil {
				wgDialer := wgnet.New(cfg)
				if err = wgDialer.Open(); err == nil {
					dialer = wgDialer
					closer = wgDialer
				} else {
					err = errors.Join(ErrOpenWireGuardDevice, err)
				}
			} else {
				err = errors.Join(ErrParseWireGuardConfig, err)
			}
		} else {
			err = errors.Join(ErrOpenWireGuardConfig, err)
		}
	}
	return
}

func newOrderRootsContext(timeoutSeconds int) (ctx context.Context, cancel context.CancelFunc) {
	timeout := time.Second * time.Duration(timeoutSeconds)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	return
}

// Query contexts are intentionally detached from startup contexts so one expired
// setup timeout does not cancel subsequent queries.
func newPerQueryContext(_ context.Context, maxwaitMillis int) (ctx context.Context, cancel context.CancelFunc) {
	timeout := time.Millisecond * time.Duration(maxwaitMillis)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	return
}

func recordFn(_ *recursive.Recursive, nsaddr netip.Addr, qtype uint16, qname string, m *dns.Msg, err error) {
	fmt.Println("\n;;; ----------------------------------------------------------------------")
	fmt.Printf("; <<>> recursive <<>> @%s %s %s\n", nsaddr, dns.Type(qtype), qname)
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
		defer closeWithLog(*flagCpuprofile, f)
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

	roots4 := []netip.Addr{}
	roots6 := []netip.Addr{}
	if *flag4 {
		roots4 = recursive.Roots4
	}
	if *flag6 {
		roots6 = recursive.Roots6
	}

	if len(qnames) == 0 {
		fmt.Println("missing one or more names to query")
		return
	}

	orderRootsCtx, cancelOrderRootsCtx := newOrderRootsContext(*flagTimeout)
	defer cancelOrderRootsCtx()

	maxrate := int32(*flagRatelimit) // #nosec G115
	var rateLimiter <-chan struct{}
	if maxrate > 0 {
		rateLimiter = rate.NewTicker(nil, &maxrate).C
	}

	var dialer proxy.ContextDialer
	var dialerCloser io.Closer
	var err error
	if dialer, dialerCloser, err = newWireGuardDialer(*flagWgConfig); err == nil {
		defer closeWithLog(*flagWgConfig, dialerCloser)
	} else {
		log.Fatal(err)
	}

	rec := recursive.NewWithOptions(dialer, recursive.DefaultCache, roots4, roots6, rateLimiter)
	setResolverQueryTimeout(rec, *flagTimeout)
	rec.OrderRoots(orderRootsCtx)
	if *flagDeterministic {
		rec.Deterministic = true
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
			queryCtx, cancel := newPerQueryContext(orderRootsCtx, *flagMaxwait)
			retv, srv, err := rec.ResolveWithOptions(queryCtx, recursive.DefaultCache, dbgout, qname, qtype)
			recordFn(rec, srv, qtype, qname, retv, err)
			cancel()
		}
	}

	fmt.Printf(";; CACHE: size %d, hit ratio %.2f%%\n", recursive.DefaultCache.Entries(), recursive.DefaultCache.HitRatio())

	if *flagMemprofile != "" {
		f, err := os.Create(*flagMemprofile)
		if err != nil {
			log.Fatal(err)
		}
		defer closeWithLog(*flagMemprofile, f)
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}
