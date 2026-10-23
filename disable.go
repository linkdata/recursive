package recursive

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

func (r *Recursive) usingUDP() (yes bool) {
	r.mu.RLock()
	yes = r.useUDP
	r.mu.RUnlock()
	return
}

func (r *Recursive) usingIPv6() (yes bool) {
	r.mu.RLock()
	yes = r.useIPv6
	r.mu.RUnlock()
	return
}

func (r *Recursive) maybeDisableIPv6(err error) (disabled bool) {
	if err != nil {
		errstr := err.Error()
		if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
			strings.Contains(errstr, "network is unreachable") || strings.Contains(errstr, "no route to host") {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.useIPv6 {
				r.useIPv6 = false
				disabled = true
				roots := make([]netip.Addr, 0, len(r.rootServers))
				for _, addr := range r.rootServers {
					if addr.Is4() {
						roots = append(roots, addr)
					}
				}
				r.rootServers = roots
			}
		}
	}
	return
}

func (r *Recursive) maybeDisableUdp(err error) (disabled bool) {
	var ne net.Error
	if errors.As(err, &ne) && !ne.Timeout() {
		errstr := err.Error()
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EPROTONOSUPPORT) || strings.Contains(errstr, "network not implemented") {
			r.mu.Lock()
			disabled = r.useUDP
			r.useUDP = false
			r.mu.Unlock()
		}
	}
	return
}
