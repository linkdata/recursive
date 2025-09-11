package recursive

import (
	"time"
)

// netError wraps a network error with a timestamp
type netError struct {
	Err  error
	When time.Time
}

func (ne netError) Error() string {
	return ne.Err.Error()
}

func (ne netError) Unwrap() error {
	return ne.Err
}
