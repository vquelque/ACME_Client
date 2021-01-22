package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
)

func main() {

	var dirURL string
	var record string
	var domainStr string
	//var domains []string
	var revoke bool
	var rootCertif string
	var challenge string

	flag.StringVar(&dirURL, "dir", "", "ACME server directory URL")
	flag.StringVar(&record, "record", "", "IPv4 address which must be returned by the DNS server for all A-record queries.")
	flag.StringVar(&domainStr, "domain", "", "domain(s) for  which to request the certificate")
	flag.StringVar(&rootCertif, "cert", "", "path to trust anchor to check server certif")
	flag.StringVar(&challenge, "challenge", "http01", "challenge to be used for authorization")
	flag.BoolVar(&revoke, "revoke", false, "revoke certificate if set to true")
	flag.Parse()

	if dirURL == "" {
		log.Fatal("directory url cannot be empty")
	}
	if record == "" {
		log.Fatal("record cannot be empty")
	}
	if domainStr == "" {
		log.Fatal("domain cannot be empty")
	}
	if challenge == "" {
		log.Fatal("challenge cannot be empty")
	}
	if rootCertif == "" {
		log.Fatal("root certificate cannot be empty")
	}

	domains := strings.Split(domainStr, ",")

	//start acme dns server
	DNSHandler := make(chan []string) // channel for sending dns TXT challenges
	err := StartDNSServer(record, 10053, DNSHandler)
	if err != nil {
		log.Print(err)
	}

	c := NewACMEClient(dirURL, rootCertif, record)
	acc, err := c.NewAccount()
	if err != nil {
		log.Print(err)
	}
	c.account = acc
	certs, err := c.RequestCertificateForDomains(domains, challenge, DNSHandler)
	if err != nil {
		log.Print(err)
		return
	}
	log.Printf("certificate successfully obtained : %v", certs[0].DNSNames)
	if revoke {
		err := c.RevokeCertificate(certs[0])
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("certificate for domain %s have been successfully revoked", certs[0].DNSNames)
	}
	// Start new HTTPS server with certificate

	certSrv := NewCertificateHTTPSServer(record, certs[0], c.certPrivateKey)
	StartCertificateHTTPSServer(certSrv)
	//shutdown server
	mux := http.NewServeMux()
	shutdownSrv := &http.Server{Addr: record + ":5003", Handler: mux}
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		StopServer(shutdownSrv)
		StopServer(certSrv)
		return //exit program
	})
	shutdownSrv.ListenAndServe() //blocking
}
