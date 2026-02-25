package recursive

import (
	"fmt"

	"github.com/miekg/dns"
)

type MismatchedQuestionError struct {
	ExpectedQName string
	ExpectedQType uint16
	ActualQName   string
	ActualQType   uint16
}

func (e *MismatchedQuestionError) Error() string {
	return fmt.Sprintf(
		"mismatched response question expected=%q/%s actual=%q/%s",
		e.ExpectedQName,
		dns.Type(e.ExpectedQType),
		e.ActualQName,
		dns.Type(e.ActualQType),
	)
}

func (*MismatchedQuestionError) Is(target error) bool {
	_, ok := target.(*MismatchedQuestionError)
	return ok
}

// ErrMismatchedQuestion is returned when a response question does not match the query.
var ErrMismatchedQuestion = &MismatchedQuestionError{}
