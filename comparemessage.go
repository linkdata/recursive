package recursive

import (
	"fmt"
	"io"

	"github.com/miekg/dns"
)

// CompareMessage compares two DNS messages for semantic equivalence.
//
// It compares the response code and records in Answer, Authority, and Extra.
// Differences in TTL values, OPT pseudo-records, and record ordering are
// ignored. Any discovered differences are written as plain text to w.
func CompareMessage(a, b *dns.Msg, w io.Writer) (equivalent bool) {
	out := io.Discard
	if w != nil {
		out = w
	}

	equivalent = true
	if !compareRcode(a, b, out) {
		equivalent = false
	}
	if !compareSectionRRs("answer", msgAnswer(a), msgAnswer(b), out) {
		equivalent = false
	}
	if !compareSectionRRs("authority", msgAuthority(a), msgAuthority(b), out) {
		equivalent = false
	}
	if !compareSectionRRs("extra", msgExtra(a), msgExtra(b), out) {
		equivalent = false
	}
	return
}

func compareRcode(a, b *dns.Msg, w io.Writer) (equivalent bool) {
	equivalent = true
	if a != nil || b != nil {
		if a == nil || b == nil {
			equivalent = false
		} else {
			equivalent = a.Rcode == b.Rcode
		}
		if !equivalent {
			_, _ = fmt.Fprintf(w, "rcode differs: a=%s b=%s\n", messageRcodeString(a), messageRcodeString(b))
		}
	}
	return
}

func compareSectionRRs(section string, a, b []dns.RR, w io.Writer) (equivalent bool) {
	aComparable := comparableRRs(a)
	bComparable := comparableRRs(b)
	unmatchedB := append([]dns.RR(nil), bComparable...)
	equivalent = true

	for _, aRR := range aComparable {
		matchIdx := matchingRRIndex(aRR, unmatchedB)
		if matchIdx >= 0 {
			unmatchedB = append(unmatchedB[:matchIdx], unmatchedB[matchIdx+1:]...)
		} else {
			equivalent = false
			_, _ = fmt.Fprintf(w, "%s only in a: %s\n", section, rrText(aRR))
		}
	}

	for _, bRR := range unmatchedB {
		equivalent = false
		_, _ = fmt.Fprintf(w, "%s only in b: %s\n", section, rrText(bRR))
	}

	return
}

func comparableRRs(rrs []dns.RR) (out []dns.RR) {
	out = make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		include := true
		if rr != nil {
			hdr := rr.Header()
			if hdr != nil {
				include = hdr.Rrtype != dns.TypeOPT
			}
		}
		if include {
			out = append(out, rr)
		}
	}
	return
}

func matchingRRIndex(target dns.RR, candidates []dns.RR) (idx int) {
	idx = -1
	for i, candidate := range candidates {
		if rrsEquivalent(target, candidate) {
			idx = i
			break
		}
	}
	return
}

func rrsEquivalent(a, b dns.RR) (equivalent bool) {
	if a == nil || b == nil {
		equivalent = a == b
	} else {
		equivalent = dns.IsDuplicate(a, b)
	}
	return
}

func rrText(rr dns.RR) (s string) {
	s = "<nil>"
	if rr != nil {
		s = rr.String()
	}
	return
}

func messageRcodeString(msg *dns.Msg) (s string) {
	s = "<nil>"
	if msg != nil {
		s = dns.RcodeToString[msg.Rcode]
		if s == "" {
			s = fmt.Sprintf("RCODE(%d)", msg.Rcode)
		}
	}
	return
}

func msgAnswer(msg *dns.Msg) (answer []dns.RR) {
	if msg != nil {
		answer = msg.Answer
	}
	return
}

func msgAuthority(msg *dns.Msg) (authority []dns.RR) {
	if msg != nil {
		authority = msg.Ns
	}
	return
}

func msgExtra(msg *dns.Msg) (extra []dns.RR) {
	if msg != nil {
		extra = msg.Extra
	}
	return
}
