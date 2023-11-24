package recursive

import (
	"fmt"
	"net/netip"
)

type cacheKey struct {
	nsaddr netip.Addr
	qname  string
	qtype  uint16
}

func (q cacheKey) String() string {
	return fmt.Sprintf("cacheKey{%q, %q, %s}", q.nsaddr.String(), q.qname, DnsTypeToString(q.qtype))
}
