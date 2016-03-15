package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"../cert"
	"../session"
)

var (
	port                = flag.Int("port", 443, "Port to serve on.")
	entityFile          = flag.String("entity_file", "", "File containing PGP entity used to encrypt/decrypt password entries.")
	baseDir             = flag.String("base_dir", "", "Base directory of password store.")
	sessionDuration     = flag.Duration("session_duration", time.Minute, "Length of sessions (without interaction).")
	certFile            = flag.String("cert_file", "", "File containing TLS certificate.")
	keyFile             = flag.String("key_file", "", "File containing TLS certificate key.")
	certRefreshInterval = flag.Duration("cert_refresh_interval", 7*24*time.Hour, "Interval at which TLS certificate is refreshed.")
)

func contentHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s requested %s", r.RemoteAddr, r.RequestURI)

	w.WriteHeader(404)
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
	if *certFile == "" {
		log.Fatalf("--cert_file is required")
	}
	if *keyFile == "" {
		log.Fatalf("--key_file is required")
	}
	if *certRefreshInterval <= 0 {
		log.Fatalf("--cert_refresh_interval must be positive")
	}

	// Create session handler.
	sEntity, err := ioutil.ReadFile(*entityFile)
	if err != nil {
		log.Fatalf("Could not read entity: %v", err)
	}
	sessHandler, err := session.NewHandler(sEntity, *baseDir, *sessionDuration)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}
	_ = sessHandler // TODO: remove

	// Create certificate cache.
	certCache, err := cert.NewCache(*certFile, *keyFile, *certRefreshInterval)
	if err != nil {
		log.Fatalf("Could not create cert cache: %v", err)
	}

	// Start serving.
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: http.HandlerFunc(contentHandler),
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			CipherSuites:   []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			Certificates:   []tls.Certificate{*certCache.Get()}, // This will never be used, but is required.
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certCache.Get(), nil },
		},
	}
	log.Printf("Serving")
	log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
}
