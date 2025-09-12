// Package dnstest provides a configurable DNS server simulator for tests.
package dnstest

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Response defines how the server should answer a specific DNS question.
type Response struct {
	// Msg is sent as the response if non-nil. The Question and Id are set from
	// the incoming request before sending.
	Msg *dns.Msg
	// Rcode is used if Msg is nil to set the reply code in the generated
	// message. Defaults to RcodeSuccess.
	Rcode int
	// Raw is written directly on the wire instead of Msg/Rcode allowing
	// responses with malformed DNS packets.
	Raw []byte
	// Drop causes the server to ignore the request simulating a timeout.
	Drop bool
	// Delay adds an optional delay before processing the response.
	Delay time.Duration
}

// Server simulates a DNS server for use in tests.
type Server struct {
	// Addr is the address the server is listening on.
	Addr string

	responses map[string]*Response
	udp       *dns.Server
	tcp       *dns.Server
}

// NewServer starts a new DNS server on addr serving the provided responses.
// The same address and port are used for both UDP and TCP. If the port in addr
// is "0" an available port will be chosen automatically.
func NewServer(addr string, responses map[string]*Response) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	tcpListener, err := net.Listen("tcp", udpConn.LocalAddr().String())
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}

	s := &Server{
		Addr:      udpConn.LocalAddr().String(),
		responses: responses,
	}
	handler := dns.HandlerFunc(s.handle)
	s.udp = &dns.Server{PacketConn: udpConn, Handler: handler}
	s.tcp = &dns.Server{Listener: tcpListener, Handler: handler}

	go s.udp.ActivateAndServe()
	go s.tcp.ActivateAndServe()

	return s, nil
}

// Close shuts down the server.
func (s *Server) Close() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		_ = w.Close()
		return
	}
	q := req.Question[0]
	key := Key(q.Name, q.Qtype)
	resp, ok := s.responses[key]
	if !ok {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	if resp.Delay > 0 {
		time.Sleep(resp.Delay)
	}
	if resp.Drop {
		return
	}
	if resp.Raw != nil {
		_, _ = w.Write(resp.Raw)
		return
	}
	var m *dns.Msg
	if resp.Msg != nil {
		m = resp.Msg.Copy()
		// Preserve resource records from the original message after SetReply.
		ans, ns, extra := m.Answer, m.Ns, m.Extra
		m.SetReply(req)
		m.Answer, m.Ns, m.Extra = ans, ns, extra
	} else {
		m = new(dns.Msg)
		m.SetReply(req)
	}
	if resp.Rcode != 0 {
		m.Rcode = resp.Rcode
	}
	_ = w.WriteMsg(m)
}

// Key returns a map key for the given question name and type.
func Key(name string, qtype uint16) string {
	return strings.ToLower(name) + "/" + strconv.FormatUint(uint64(qtype), 10)
}
