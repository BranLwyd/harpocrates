package main

import (
	"crypto/tls"
	"flag"
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
)

var (
	entityFile      = flag.String("entity_file", "", "File containing PGP entity used to encrypt/decrypt password entries.")
	baseDir         = flag.String("base_dir", "", "Base directory of password store.")
	sessionDuration = flag.Duration("session_duration", time.Minute, "Length of sessions (without interaction).")
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
	// Check flags.
	flag.Parse()
	if *entityFile == "" {
		log.Fatalf("--entity_file is required")
	}
	if *baseDir == "" {
		log.Fatalf("--base_dir is required")
	}
	if *sessionDuration <= 0 {
		log.Fatalf("--session_duration must be positive")
	}

	// Create session handler & API.
	sEntity, err := ioutil.ReadFile(*entityFile)
	if err != nil {
		log.Fatalf("Could not read entity: %v", err)
	}
	sessHandler, err := session.NewHandler(sEntity, *baseDir, *sessionDuration)
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
