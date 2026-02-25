package recursive

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

type comparableSections struct {
	answer    []dns.RR
	authority []dns.RR
	extra     []dns.RR
}

// CompareMessage compares two DNS messages and returns ordering information.
//
// It compares the response code and records in Answer, Authority, and Extra.
// Differences in TTL values, OPT pseudo-records, and record ordering are
// ignored. Any discovered differences are written as plain text to w.
//
// Return values:
//   - -1 if a has less data than b
//   - +1 if a has more data than b
//   - 0 if the messages are equivalent
func CompareMessage(a, b *dns.Msg, w io.Writer) (cmp int) {
	out := io.Discard
	if w != nil {
		out = w
	}

	aSections := newComparableSections(a)
	bSections := newComparableSections(b)

	equivalent := true
	if !compareRcode(a, b, out) {
		equivalent = false
	}
	if !compareSectionRRs("answer", aSections.answer, bSections.answer, out) {
		equivalent = false
	}
	if !compareSectionRRs("authority", aSections.authority, bSections.authority, out) {
		equivalent = false
	}
	if !compareSectionRRs("extra", aSections.extra, bSections.extra, out) {
		equivalent = false
	}
	if !equivalent {
		cmp = compareMessageOrdering(a, b, aSections, bSections)
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
	unmatchedB := append([]dns.RR(nil), b...)
	equivalent = true

	for _, aRR := range a {
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

func compareMessageOrdering(a, b *dns.Msg, aSections, bSections comparableSections) (cmp int) {
	aDataCount := len(aSections.answer) + len(aSections.authority) + len(aSections.extra)
	bDataCount := len(bSections.answer) + len(bSections.authority) + len(bSections.extra)
	cmp = compareInt(aDataCount, bDataCount)
	if cmp == 0 {
		cmp = compareInt(messageRcodeValue(a), messageRcodeValue(b))
	}
	if cmp == 0 {
		cmp = compareInt(len(aSections.answer), len(bSections.answer))
	}
	if cmp == 0 {
		cmp = compareInt(len(aSections.authority), len(bSections.authority))
	}
	if cmp == 0 {
		cmp = compareInt(len(aSections.extra), len(bSections.extra))
	}
	if cmp == 0 {
		cmp = compareMsgHdrWithoutRcode(a, b)
	}
	if cmp == 0 {
		cmp = compareRRLists(aSections.answer, bSections.answer)
	}
	if cmp == 0 {
		cmp = compareRRLists(aSections.authority, bSections.authority)
	}
	if cmp == 0 {
		cmp = compareRRLists(aSections.extra, bSections.extra)
	}
	if cmp == 0 {
		cmp = compareQuestionLists(msgQuestion(a), msgQuestion(b))
	}
	return
}

func compareMsgHdrWithoutRcode(a, b *dns.Msg) (cmp int) {
	hdrA := messageHdr(a)
	hdrB := messageHdr(b)
	cmp = compareUint16(hdrA.Id, hdrB.Id)
	if cmp == 0 {
		cmp = compareBool(hdrA.Response, hdrB.Response)
	}
	if cmp == 0 {
		cmp = compareInt(hdrA.Opcode, hdrB.Opcode)
	}
	if cmp == 0 {
		cmp = compareBool(hdrA.Authoritative, hdrB.Authoritative)
	}
	if cmp == 0 {
		cmp = compareBool(hdrA.Truncated, hdrB.Truncated)
	}
	if cmp == 0 {
		cmp = compareBool(hdrA.RecursionDesired, hdrB.RecursionDesired)
	}
	if cmp == 0 {
		cmp = compareBool(hdrA.RecursionAvailable, hdrB.RecursionAvailable)
	}
	if cmp == 0 {
		cmp = compareBool(hdrA.Zero, hdrB.Zero)
	}
	if cmp == 0 {
		cmp = compareBool(hdrA.AuthenticatedData, hdrB.AuthenticatedData)
	}
	if cmp == 0 {
		cmp = compareBool(hdrA.CheckingDisabled, hdrB.CheckingDisabled)
	}
	return
}

func compareRRLists(a, b []dns.RR) (cmp int) {
	keysA := rrKeys(a)
	keysB := rrKeys(b)
	cmp = compareInt(len(keysA), len(keysB))
	if cmp == 0 {
		for i := 0; i < len(keysA) && cmp == 0; i++ {
			cmp = strings.Compare(keysA[i], keysB[i])
		}
	}
	return
}

func rrKeys(rrs []dns.RR) (keys []string) {
	keys = make([]string, 0, len(rrs))
	for _, rr := range rrs {
		keys = append(keys, rrKey(rr))
	}
	sort.Strings(keys)
	return
}

func rrKey(rr dns.RR) (key string) {
	key = "<nil>"
	if rr != nil {
		rrCopy := dns.Copy(rr)
		if rrCopy != nil {
			hdr := rrCopy.Header()
			if hdr != nil {
				hdr.Ttl = 0
			}
			rrLen := dns.Len(rrCopy)
			if rrLen > 0 {
				wire := make([]byte, rrLen)
				off, err := dns.PackRR(rrCopy, wire, 0, nil, false)
				if err == nil && off > 0 {
					key = string(wire[:off])
				} else {
					key = rrCopy.String()
				}
			} else {
				key = rrCopy.String()
			}
		}
	}
	return
}

func compareQuestionLists(a, b []dns.Question) (cmp int) {
	keysA := questionKeys(a)
	keysB := questionKeys(b)
	cmp = compareInt(len(keysA), len(keysB))
	if cmp == 0 {
		for i := 0; i < len(keysA) && cmp == 0; i++ {
			cmp = strings.Compare(keysA[i], keysB[i])
		}
	}
	return
}

func questionKeys(questions []dns.Question) (keys []string) {
	keys = make([]string, 0, len(questions))
	for _, question := range questions {
		keys = append(keys, fmt.Sprintf("%s|%d|%d", dns.CanonicalName(question.Name), question.Qtype, question.Qclass))
	}
	sort.Strings(keys)
	return
}

func compareInt(a, b int) (cmp int) {
	if a < b {
		cmp = -1
	} else {
		if a > b {
			cmp = 1
		}
	}
	return
}

func compareUint16(a, b uint16) (cmp int) {
	if a < b {
		cmp = -1
	} else {
		if a > b {
			cmp = 1
		}
	}
	return
}

func compareBool(a, b bool) (cmp int) {
	cmp = compareInt(boolToInt(a), boolToInt(b))
	return
}

func boolToInt(v bool) (n int) {
	if v {
		n = 1
	}
	return
}

func messageHdr(msg *dns.Msg) (hdr dns.MsgHdr) {
	if msg != nil {
		hdr = msg.MsgHdr
	}
	return
}

func messageRcodeValue(msg *dns.Msg) (rcode int) {
	rcode = -1
	if msg != nil {
		rcode = msg.Rcode
	}
	return
}

func newComparableSections(msg *dns.Msg) (sections comparableSections) {
	sections.answer = comparableRRs(msgAnswer(msg))
	sections.authority = comparableRRs(msgAuthority(msg))
	sections.extra = comparableRRs(msgExtra(msg))
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

func msgQuestion(msg *dns.Msg) (questions []dns.Question) {
	if msg != nil {
		questions = msg.Question
	}
	return
}
