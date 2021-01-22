package main

import (
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

// StartDNSServer starts the DNS server used to handle all ACME DNS requests
func StartDNSServer(ip string, port int, challenge chan []string) error {
	if ip == "" {
		return fmt.Errorf("please provide an ip for dns server")
	}
	addr := ip + ":" + strconv.Itoa(port)
	srv := &dns.Server{Addr: addr, Net: "udp"}
	var lastToken []string
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeA:
			msg.Authoritative = true
			domain := msg.Question[0].Name
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
		case dns.TypeTXT:
			log.Print("received dns challenge request ")
			select {
			case auth := <-challenge:
				if len(auth) != 2 {
					log.Print("missing an argument for constructing challenge validation TXT record")
				}
				lastToken = auth
				break
			default:
				break
			}
			if lastToken != nil {
				log.Print("token available for dns challenge request ")
				msg.Authoritative = true
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: lastToken[0], Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{lastToken[1]},
				})
				break
			}

		}
		w.WriteMsg(&msg)

	})
	go func() {
		log.Printf("dns server started at address : %s", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()
	return nil
}
