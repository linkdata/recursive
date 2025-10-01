package recursive

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"
)

func (r *Recursive) OrderRoots(ctx context.Context) {
	r.OrderRootsTimeout(ctx, time.Second)
}

// OrderRootsTimeout sorts the root server list by their current latency and removes those that don't respond within cutoff.
func (r *Recursive) OrderRootsTimeout(ctx context.Context, cutoff time.Duration) {
	if _, ok := ctx.Deadline(); !ok {
		newctx, cancel := context.WithTimeout(ctx, cutoff*2)
		defer cancel()
		ctx = newctx
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var l []*rootRtt
	var wg sync.WaitGroup
	for _, addr := range r.rootServers {
		rt := &rootRtt{addr: addr}
		l = append(l, rt)
		wg.Add(1)
		go timeRoot(ctx, r, &wg, rt)
	}
	wg.Wait()
	sort.Slice(l, func(i, j int) bool { return l[i].rtt < l[j].rtt })
	var newRootServers []netip.Addr
	useIPv4 := false
	useIPv6 := false
	for _, rt := range l {
		if rt.rtt <= cutoff {
			useIPv4 = useIPv4 || rt.addr.Is4()
			useIPv6 = useIPv6 || rt.addr.Is6()
			newRootServers = append(newRootServers, rt.addr)
		}
	}
	if len(newRootServers) > 0 {
		r.rootServers = newRootServers
		r.useIPv4 = useIPv4
		r.useIPv6 = useIPv6
	}
}
