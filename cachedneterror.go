package recursive

import (
	"fmt"
	"net/netip"
	"time"
)

type CachedNetError struct {
	When     time.Time
	Err      error
	Protocol string
	Address  netip.Addr
}

func (ne CachedNetError) Error() string {
	return fmt.Sprintf("(cached) %v %v: %v", ne.Protocol, ne.Address, ne.Err.Error())
}

func (ne CachedNetError) Unwrap() error {
	return ne.Err
}
