package recursive

import (
	"net/netip"
)

type cacheKey struct {
	nsaddr netip.Addr
	qname  string
}
