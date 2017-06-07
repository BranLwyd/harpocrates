// +build !debug

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"../handler"
	"../session"
)

var (
	configFile = flag.String("config", "", "The harpd configuration file to use.")
)

func parseConfig() (_ *config, serializedEntity string, _ *session.CounterStore) {
	// Sanity check flags.
	if *configFile == "" {
		log.Fatalf("--config is required")
	}

	// Set a few sensible defaults and then read & parse the config.
	cfg := &config{
		SessionDurationSecs: 300,
		NewSessionRate:      1,
	}
	cfgBytes, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Could not read config file: %v", err)
	}
	if err := json.Unmarshal(cfgBytes, cfg); err != nil {
		log.Fatalf("Could not parse config file: %v", err)
	}

	// Sanity check config values.
	if cfg.HostName == "" {
		log.Fatalf("host_name is required in config")
	}
	if cfg.Email == "" {
		log.Fatalf("email is required in config")
	}
	if cfg.CertDir == "" {
		log.Fatalf("cert_dir is required in config")
	}
	if cfg.PassDir == "" {
		log.Fatalf("pass_dir is required in config")
	}
	if cfg.KeyFile == "" {
		log.Fatalf("key_file is required in config")
	}
	if cfg.CounterFile == "" {
		log.Fatalf("counter_file is required in config")
	}
	if cfg.AlertCmd == "" {
		log.Printf("No alert_cmd specified, logging alerts")
	}
	if cfg.SessionDurationSecs <= 0 {
		log.Fatalf("session_duration_s must be positive")
	}
	if cfg.NewSessionRate <= 0 {
		log.Fatalf("new_session_rate must be positive")
	}

	// Create serialized entity, counter store based on config.
	seBytes, err := ioutil.ReadFile(cfg.KeyFile)
	if err != nil {
		log.Fatalf("Could not read key file: %v", err)
	}
	se := string(seBytes)

	cs, err := session.NewCounterStore(cfg.CounterFile)
	if err != nil {
		log.Fatalf("Could not create U2F counter store: %v", err)
	}

	return cfg, se, cs
}

func serve(cfg *config, h http.Handler) {
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.HostName),
		Cache:      autocert.DirCache(cfg.CertDir),
		Email:      cfg.Email,
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
		Handler:      handler.NewLogging("https", handler.NewSecureHeader(h)),
	}
	log.Printf("Serving")
	log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
}
