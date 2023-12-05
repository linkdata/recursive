package recursive

import (
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

type cacheValue struct {
	*dns.Msg
	nsaddr  netip.Addr
	expires time.Time
}
