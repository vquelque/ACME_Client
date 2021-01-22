package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
)

func serverChallenge(authorization string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("received http request on challenge endpoint")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(authorization))
	})
}

func newChallengeHTTPServer(token string, authorization string, ip string) *http.Server {
	url := fmt.Sprintf("/.well-known/acme-challenge/%s", token)
	mux := http.NewServeMux()
	mux.Handle(url, serverChallenge(authorization))
	return &http.Server{Addr: ip + ":5002", Handler: mux}
}

// StartHTTPChallengeServer starts provided server
func StartHTTPChallengeServer(srv *http.Server) {
	go func() {
		log.Printf("challenge server started at %s", srv.Addr)
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("unable to start challenge http server %s", err)
		}
	}()
}

// StopHTTPChallengeServer stops provided server
func StopHTTPChallengeServer(srv *http.Server) {
	srv.Shutdown(context.Background())
}
