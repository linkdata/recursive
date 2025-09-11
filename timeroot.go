package recursive

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// rootRtt stores round-trip time measurements for a root server
type rootRtt struct {
	addr netip.Addr
	rtt  time.Duration
}

// timeRoot measures the RTT to a root server by making multiple connection attempts
func timeRoot(ctx context.Context, dialer proxy.ContextDialer, wg *sync.WaitGroup, rt *rootRtt) {
	defer wg.Done()

	const numProbes = 3

	network := "tcp4"
	if rt.addr.Is6() {
		network = "tcp6"
	}

	rt.rtt = time.Hour // Default to very high if all probes fail

	var totalRtt time.Duration
	successfulProbes := 0

	for i := 0; i < numProbes; i++ {
		start := time.Now()
		conn, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(rt.addr, dnsPort).String())
		if err != nil {
			continue
		}

		totalRtt += time.Since(start)
		successfulProbes++
		_ = conn.Close()
	}

	if successfulProbes > 0 {
		rt.rtt = totalRtt / time.Duration(successfulProbes)
	}
}
