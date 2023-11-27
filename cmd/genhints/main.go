package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"text/template"

	"github.com/miekg/dns"
)

//go:embed roothints.go.tmpl
var roothintsgotmpl string

type Roots struct {
	Roots4 []netip.Addr
	Roots6 []netip.Addr
}

func main() {
	resp, err := http.Get("https://www.internic.net/domain/named.root")
	if err == nil {
		defer resp.Body.Close()
		var body []byte
		if body, err = io.ReadAll(resp.Body); err == nil {
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
						defer of.Close()
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
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
