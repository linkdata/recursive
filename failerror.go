package recursive

type failError struct{ e error }

func (fe failError) Unwrap() error        { return fe.e }
func (fe failError) Is(target error) bool { return target == ErrNoResponse }
func (fe failError) Error() (s string)    { return fe.e.Error() }
