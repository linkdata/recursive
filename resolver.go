package recursive

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

type Resolver interface {
	Resolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error)
}
