package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"time"

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
	debug = flag.Bool("debug", false, "If set, serve over HTTP 8080 instead of HTTPS 443.")
)

func main() {
	// Handle flags.
	flag.Parse()

	pd := passDir
	kf := keyFile
	if *debug {
		// Debug build uses current directory.
		pd = "pass/"
		kf = "key"
	}

	// Create session handler & content handler.
	sEntity, err := ioutil.ReadFile(kf)
	if err != nil {
		log.Fatalf("Could not read entity: %v", err)
	}
	_, err = session.NewHandler(sEntity, pd, 5*time.Minute)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}
	ch, err := contentHandler()
	if err != nil {
		log.Fatalf("Could not initialize content handler: %v", err)
	}

	// Start serving.
	if *debug {
		server := &http.Server{
			Addr:    "127.0.0.1:8080",
			Handler: NewLoggingHandler("debug", ch),
		}
		log.Printf("Serving debug")
		log.Fatalf("Error while serving: %v", server.ListenAndServe())
	}

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
		Handler:      NewLoggingHandler("https", ch),
	}
	log.Printf("Serving")
	log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
}
