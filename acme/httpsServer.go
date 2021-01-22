package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
)

// NewCertificateHTTPSServer creates a new https server that returns provided certificate on GET requests
func NewCertificateHTTPSServer(ip string, certificate *x509.Certificate, privateKey *ecdsa.PrivateKey) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(certificate.Raw)
	})
	tlsCert := tls.Certificate{Certificate: [][]byte{certificate.Raw}, PrivateKey: privateKey}
	return &http.Server{Addr: ip + ":5001", Handler: mux, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}}
}

// StartCertificateHTTPSServer starts the provided server in another go routine
func StartCertificateHTTPSServer(srv *http.Server) {
	go func() {
		log.Printf("certificate https server started at %s", srv.Addr)
		err := srv.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("unable to start certificate https server %s", err)
		}
	}()
}

// StopServer stops the provided server
func StopServer(srv *http.Server) {
	srv.Shutdown(context.Background())
}
