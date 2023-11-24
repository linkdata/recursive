package recursive

import (
	"time"

	"github.com/miekg/dns"
)

type cacheValue struct {
	*dns.Msg
	expires time.Time
}
