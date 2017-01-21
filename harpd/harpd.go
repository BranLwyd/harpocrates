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
	ctrFile = "/var/lib/harpd/u2fctr"
	u2fReg  = "BQTh/D3Xi2VkWvc0mTicoUJeKnPnk3GgVla5JCvPcPhWkAtnCtAmW6bLIG9NHnZkNHUmKcmLTTlwvvs4Zfz+IKhbQAWYk1rzJYmMqdidWgaRlgmrDPL3gnPc1PATwUxUshRuuJVOvDqxvhzHMj4v3ziKs78obxZ4XFCVYTNZUPO+nnEwggJEMIIBLqADAgECAgRVYr6gMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTQzMjUzNDY4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEszH3c9gUS5mVy+RYVRfhdYOqR2I2lcvoWsSCyAGfLJuUZ64EWw5m8TGy6jJDyR/aYC4xjz/F2NKnq65yvRQwmjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMAsGCSqGSIb3DQEBCwOCAQEArBbZs262s6m3bXWUs09Z9Pc+28n96yk162tFHKv0HSXT5xYU10cmBMpypXjjI+23YARoXwXn0bm+BdtulED6xc/JMqbK+uhSmXcu2wJ4ICA81BQdPutvaizpnjlXgDJjq6uNbsSAp98IStLLp7fW13yUw+vAsWb5YFfK9f46Yx6iakM3YqNvvs9M9EUJYl/VrxBJqnyLx2iaZlnpr13o8NcsKIJRdMUOBqt/ageQg3ttsyq/3LyoNcu7CQ7x8NmeCGm/6eVnZMQjDmwFdymwEN4OxfnM5MkcKCYhjqgIGruWkVHsFnJa8qjZXneVvKoiepuUQyDEJ2GcqvhU2YKY1zBFAiB2afTDsR6rPnfYBSk6qpYf7UXUa9oXxPeJDMOuWHNlOAIhAIM14GSSI8rhLhWCMiFLEzD9T1G7SbfHS37fgGwyQgal"
)

var (
	debug = flag.Bool("debug", false, "If set, serve over HTTP 8080 instead of HTTPS 443.")
)

func main() {
	// Handle flags.
	flag.Parse()

	pd := passDir
	kf := keyFile
	hn := host
	cf := ctrFile
	if *debug {
		// Debug build uses current directory.
		pd = "pass/"
		kf = "key"
		hn = "localhost:8080"
		cf = "u2fctr"
	}

	// Create session handler & content handler.
	se, err := ioutil.ReadFile(kf)
	if err != nil {
		log.Fatalf("Could not read entity: %v", err)
	}
	cs, err := session.NewCounterStore(cf)
	if err != nil {
		log.Fatalf("Could not create U2F counter store: %v", err)
	}
	sh, err := session.NewHandler(string(se), pd, hn, []string{u2fReg}, 5*time.Minute, cs)
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
