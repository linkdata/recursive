package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"text/template"
	"time"

	"github.com/miekg/dns"
)

//go:embed roothints.go.tmpl
var roothintsgotmpl string

type Roots struct {
	Roots4 []netip.Addr
	Roots6 []netip.Addr
}

var ErrUnexpectedHTTPStatus = errors.New("unexpected HTTP status")

type httpStatusError struct {
	statusCode int
}

func (e httpStatusError) Error() string {
	return "unexpected HTTP status " + strconv.Itoa(e.statusCode)
}

func (e httpStatusError) Is(err error) bool {
	return err == ErrUnexpectedHTTPStatus
}

func closeWithJoin(perr *error, c io.Closer) {
	if c != nil {
		if err := c.Close(); err != nil {
			*perr = errors.Join(*perr, err)
		}
	}
}

func fetchRootHints(client *http.Client, rootHintsURL string) (body []byte, err error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	var resp *http.Response
	if resp, err = client.Get(rootHintsURL); err == nil {
		defer closeWithJoin(&err, resp.Body)
		err = httpStatusError{statusCode: resp.StatusCode}
		if resp.StatusCode == http.StatusOK {
			body, err = io.ReadAll(resp.Body)
		}
	}
	return
}

func main() {
	client := &http.Client{Timeout: 10 * time.Second}
	body, err := fetchRootHints(client, "https://www.internic.net/domain/named.root")
	if err == nil {
		var root4, root6 []netip.Addr
		zp := dns.NewZoneParser(bytes.NewReader(body), "", "")
		for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
			switch rr := rr.(type) {
			case *dns.A:
				if ip, ok := netip.AddrFromSlice(rr.A); ok {
					if ip = ip.Unmap(); ip.Is4() {
						root4 = append(root4, ip)
						ip.AsSlice()
						if !netip.AddrFrom4(ip.As4()).Is4() {
							panic("not 4")
						}
					}
				}
			case *dns.AAAA:
				if ip, ok := netip.AddrFromSlice(rr.AAAA); ok {
					root6 = append(root6, ip)
				}
			}
		}

		sort.Slice(root4, func(i, j int) bool { return root4[i].Less(root4[j]) })
		sort.Slice(root6, func(i, j int) bool { return root6[i].Less(root6[j]) })

		if err = zp.Err(); err == nil {
			var of *os.File
			if len(os.Args) < 2 {
				of = os.Stdout
			} else {
				if of, err = os.Create(os.Args[1]); err == nil {
					defer closeWithJoin(&err, of)
				}
			}
			if err == nil {
				var t *template.Template
				if t, err = template.New("").Parse(roothintsgotmpl); err == nil {
					err = t.Execute(of, Roots{Roots4: root4, Roots6: root6})
				}
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
