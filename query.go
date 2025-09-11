package recursive

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

const cacheExtra = true // set to false to debug glue lookups

type query struct {
	*Recursive
	start  time.Time
	cache  Cacher
	logw   io.Writer
	depth  int
	nomini bool // disable QNAME minimization
	sent   int  // number of queries sent
	steps  int  // number of resolution steps
	glue   map[string][]netip.Addr
	cnames map[string]struct{}
}

type hostAddr struct {
	host string
	addr netip.Addr
}

func (ha hostAddr) String() string {
	s := ha.host
	if ha.addr.IsValid() {
		s += " " + ha.addr.String()
	}
	return s
}

func (q *query) run(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	if err = q.dive(); err != nil {
		return nil, netip.Addr{}, err
	}
	defer q.surface()

	qname = dns.CanonicalName(qname)
	msg, srv, err = q.resolveIterative(ctx, qname, qtype)

	if msg == nil {
		// Manufacture a SERVFAIL if we got nothing
		msg = new(dns.Msg)
		msg.SetQuestion(qname, qtype)
		msg.Rcode = dns.RcodeServerFailure
	} else if err == nil {
		// We got a message to return, disregard network errors
		err = nil
	}

	if q.dbg() {
		q.log("ANSWER %s for %s %q with %d records\n",
			dns.RcodeToString[msg.Rcode],
			DnsTypeToString(qtype), qname,
			len(msg.Answer))
	}

	return msg, srv, err
}

func (q *query) resolveIterative(ctx context.Context, qname string, qtype uint16) (*dns.Msg, netip.Addr, error) {
	nslist := q.getRootServers()
	var msg *dns.Msg
	var srv netip.Addr
	var err error
	var final bool
	var idx int
	var qlabel int

	for !final {
		qlabel++
		idx, final = dns.PrevLabel(qname, qlabel)
		cqname := qname[idx:]
		cqtype := dns.TypeNS

		if q.nomini {
			cqname = qname
			cqtype = qtype
		}
		if _, ok := q.glue[qname]; ok {
			cqtype = qtype
		}

		if q.dbg() {
			q.logQuery(final, cqtype, cqname, nslist)
		}

		var nsrcode int
		var gotmsg *dns.Msg

		for _, ha := range nslist {
			if !ha.addr.IsValid() {
				q.resolveGlue(ctx, &ha)
			}

			if !q.useable(ha.addr) {
				continue
			}

			gotmsg, err = q.exchange(ctx, ha.addr, cqname, cqtype)
			if err != nil {
				continue
			}

			handled, shouldContinue := q.handleResponse(ctx, gotmsg, ha, &msg, &srv, &nslist, &nsrcode, idx, qname, qtype)
			if handled {
				if shouldContinue {
					break // Move to next label
				}
				return msg, srv, err // Return immediately
			}
		}

		if !q.handleNoResponse(gotmsg, &msg, nsrcode, qname, qtype, &err) {
			break
		}
	}

	// Final resolution with the authoritative nameservers
	if msg != nil {
		msg, srv, err = q.resolveFinal(ctx, nslist, qname, qtype, msg)
	}

	return msg, srv, err
}

func (q *query) resolveGlue(ctx context.Context, ha *hostAddr) {
	if !q.needGlue(ha.host) {
		return
	}

	if q.dbg() {
		q.log("GLUE lookup for NS %q\n", ha.host)
	}

	for _, gluetype := range q.glueTypes() {
		m, _, err := q.run(ctx, ha.host, gluetype)
		if err != nil {
			continue
		}

		if m.Rcode == dns.RcodeSuccess {
			for _, rr := range m.Answer {
				if host, addr := rrHostAddr(rr); host == ha.host {
					ha.addr = addr
					q.addGlue(host, addr)
				}
			}
		}
	}
}

func (q *query) handleResponse(ctx context.Context, msg *dns.Msg, ha hostAddr,
	outMsg **dns.Msg, outSrv *netip.Addr, nsList *[]hostAddr, nsrcode *int,
	idx int, qname string, qtype uint16) (handled, shouldContinue bool) {

	switch msg.Rcode {
	case dns.RcodeSuccess:
		if msg.Authoritative || (idx > 0 && (*nsrcode == dns.RcodeNameError || len(msg.Answer) > 0)) {
			q.setCache(msg)
		}
		newlist := q.extractNS(msg)
		if len(newlist) > 0 {
			*outSrv = ha.addr
			*outMsg = msg
			*nsList = newlist
			return true, true // Continue to next label
		}

	case dns.RcodeServerFailure:
		q.setCache(msg)
		*outSrv = ha.addr
		*outMsg = msg
		return true, false // Return immediately

	case dns.RcodeRefused:
		if !q.nomini {
			if q.dbg() {
				q.log("got REFUSED, retry without QNAME minimization\n")
			}
			q.nomini = true
			*outMsg, *outSrv, _ = q.run(ctx, qname, qtype)
			return true, false // Return immediately
		}
		fallthrough

	default:
		q.setCache(msg)
		*outSrv = ha.addr
		*outMsg = msg
		return true, false // Return immediately
	}

	return false, false
}

func (q *query) handleNoResponse(gotmsg *dns.Msg, msg **dns.Msg, nsrcode int,
	qname string, qtype uint16, err *error) bool {

	if gotmsg == nil {
		if q.dbg() {
			q.log("no ANSWER for %s %q (%s)\n",
				DnsTypeToString(qtype), qname, dns.RcodeToString[nsrcode])
		}

		if *msg != nil {
			if qtype == dns.TypeNS {
				if len((*msg).Answer) == 0 {
					if len((*msg).Question) > 0 && (*msg).Question[0].Name == qname {
						(*msg).Answer, (*msg).Ns = (*msg).Ns, (*msg).Answer
					} else {
						(*msg).Rcode = nsrcode
					}
				}
			} else {
				if nsrcode != dns.RcodeSuccess {
					(*msg).SetQuestion(qname, qtype)
					(*msg).Rcode = nsrcode
				}
			}
		} else {
			*err = errors.Join(*err, ErrNoResponse)
		}
		return false
	}
	if *msg == nil {
		if q.dbg() {
			q.log("all nameservers returned SERVFAIL\n")
		}
		q.setCache(gotmsg)
		*msg = gotmsg
	}

	return true
}
