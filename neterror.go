package recursive

import "time"

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
