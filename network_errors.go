package recursive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

// Network error handling

func (r *Recursive) setNetError(protocol string, nsaddr netip.Addr, err error) (isIpv6err, isUdpErr bool) {
	if err == nil {
		return false, false
	}

	isIpv6err = nsaddr.Is6()

	// Check if this is a network error we should track
	if !r.isTrackableNetError(err) {
		return isIpv6err, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	switch protocol {
	case "udp":
		isUdpErr = true
		r.netErrors.udpErrors[nsaddr] = netError{Err: err, When: time.Now()}
	case "tcp":
		r.netErrors.tcpErrors[nsaddr] = netError{Err: err, When: time.Now()}
	}

	return isIpv6err, isUdpErr
}

func (r *Recursive) isTrackableNetError(err error) bool {
	var ne net.Error
	ok := errors.Is(err, io.EOF) || errors.As(err, &ne)
	ok = ok || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
	ok = ok || errors.Is(err, syscall.ECONNREFUSED)

	errstr := err.Error()
	ok = ok || strings.Contains(errstr, "timeout") || strings.Contains(errstr, "refused")

	return ok
}

func (r *Recursive) getUsable(ctx context.Context, protocol string, nsaddr netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var errorMap map[netip.Addr]netError
	switch protocol {
	case "udp", "udp4", "udp6":
		errorMap = r.netErrors.udpErrors
	case "tcp", "tcp4", "tcp6":
		errorMap = r.netErrors.tcpErrors
	default:
		return net.ErrClosed
	}

	r.mu.RLock()
	ne, hasNetError := errorMap[nsaddr]
	canUse := (r.config.useIPv4 && nsaddr.Is4()) || (r.config.useIPv6 && nsaddr.Is6())
	r.mu.RUnlock()

	if hasNetError {
		if time.Since(ne.When) > time.Minute {
			// Error is old, remove it
			r.mu.Lock()
			delete(errorMap, nsaddr)
			r.mu.Unlock()
			return nil
		}
		return ne
	}

	if !canUse {
		return net.ErrClosed
	}

	return nil
}

func (r *Recursive) maybeDisableIPv6(err error) bool {
	if err == nil {
		return false
	}

	if !r.isIPv6ConnectivityError(err) {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.config.useIPv6 {
		return false
	}

	r.config.useIPv6 = false

	// Remove IPv6 addresses from root servers
	var newRoots []netip.Addr
	for _, addr := range r.config.rootServers {
		if addr.Is4() {
			newRoots = append(newRoots, addr)
		}
	}
	r.config.rootServers = newRoots

	return true
}

func (r *Recursive) isIPv6ConnectivityError(err error) bool {
	errstr := err.Error()
	return errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		strings.Contains(errstr, "network is unreachable") ||
		strings.Contains(errstr, "no route to host")
}

func (r *Recursive) maybeDisableUdp(err error) bool {
	var ne net.Error
	if !errors.As(err, &ne) || ne.Timeout() {
		return false
	}

	if !r.isUDPNotSupportedError(err) {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	disabled := r.config.useUDP
	r.config.useUDP = false
	return disabled
}

func (r *Recursive) isUDPNotSupportedError(err error) bool {
	errstr := err.Error()
	return errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		strings.Contains(errstr, "network not implemented")
}
