package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"../api"
	"../session"

	"golang.org/x/crypto/acme/autocert"
)

const (
	host    = "portunus.bran.cc"
	email   = "brandon.pitman@gmail.com"
	certDir = "/var/lib/harpd/certs"
	passDir = "/var/lib/harpd/pass"
	keyFile = "/var/lib/harpd/key"
)

var (
	apiHandler *api.Handler
)

func contentHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s requested %s", r.RemoteAddr, r.URL)

	switch {
	case strings.HasPrefix(r.URL.Path, "/api/"):
		apiHandler.ServeHTTP(w, r)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

func main() {
	// Create session handler & API.
	sEntity, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Could not read entity: %v", err)
	}
	sessHandler, err := session.NewHandler(sEntity, passDir, 5*time.Minute)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}
	apiHandler = api.NewHandler(sessHandler)

	// Start serving.
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(host),
		Cache:      autocert.DirCache(certDir),
		Email:      email,
	}
	server := &http.Server{
		TLSConfig: &tls.Config{
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			GetCertificate: m.GetCertificate,
		},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      http.HandlerFunc(contentHandler),
	}
	log.Printf("Serving")
	log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
}
