package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"../handler"
	"../session"
	"../static"

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
	se, err := ioutil.ReadFile(kf)
	if err != nil {
		log.Fatalf("Could not read entity: %v", err)
	}
	sh, err := session.NewHandler(string(se), pd, 5*time.Minute)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}
	ch, err := handler.NewContent(sh)
	if err != nil {
		log.Fatalf("Could not initialize content handler: %v", err)
	}

	// Start serving.
	if *debug {
		certPEM, err := static.Asset("debug/cert.pem")
		if err != nil {
			log.Fatalf("Could not load self-signed certificate: %v", err)
		}
		keyPEM, err := static.Asset("debug/key.pem")
		if err != nil {
			log.Fatalf("Could not load self-signed certificate key: %v", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Fatalf("Could not parse self-signed certificate: %v", err)
		}
		server := &http.Server{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			Addr:    "127.0.0.1:8080",
			Handler: handler.NewLogging("debug", ch),
		}
		log.Printf("Serving debug")
		log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
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
		Handler:      handler.NewLogging("https", ch),
	}
	log.Printf("Serving")
	log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
}
