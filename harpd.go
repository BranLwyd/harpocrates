package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/BranLwyd/harpocrates/counter"
	"github.com/BranLwyd/harpocrates/handler"
	"github.com/BranLwyd/harpocrates/server"
)

var (
	configFile = flag.String("config", "", "The harpd configuration file to use.")
)

// serv implements server.Server.
type serv struct{}

func (serv) ParseConfig() (_ *server.Config, serializedEntity string, _ *counter.Store, _ error) {
	// Set a few sensible defaults and then read & parse the config.
	cfg := &server.Config{
		SessionDurationSecs: 300,
		NewSessionRate:      1,
	}
	cfgBytes, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return nil, "", nil, fmt.Errorf("could not read config file: %v", err)
	}
	if err := json.Unmarshal(cfgBytes, cfg); err != nil {
		return nil, "", nil, fmt.Errorf("could not parse config file: %v", err)
	}

	// Sanity check config values.
	if cfg.HostName == "" {
		return nil, "", nil, errors.New("host_name is required in config")
	}
	if cfg.Email == "" {
		return nil, "", nil, errors.New("email is required in config")
	}
	if cfg.CertDir == "" {
		return nil, "", nil, errors.New("cert_dir is required in config")
	}
	if cfg.PassDir == "" {
		return nil, "", nil, errors.New("pass_dir is required in config")
	}
	if cfg.KeyFile == "" {
		return nil, "", nil, errors.New("key_file is required in config")
	}
	if cfg.CounterFile == "" {
		return nil, "", nil, errors.New("counter_file is required in config")
	}
	if cfg.AlertCmd == "" {
		return nil, "", nil, errors.New("No alert_cmd specified, logging alerts")
	}
	if cfg.SessionDurationSecs <= 0 {
		return nil, "", nil, errors.New("session_duration_s must be positive")
	}
	if cfg.NewSessionRate <= 0 {
		return nil, "", nil, errors.New("new_session_rate must be positive")
	}

	// Create serialized entity, counter store based on config.
	seBytes, err := ioutil.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, "", nil, fmt.Errorf("could not read key file: %v", err)
	}
	se := string(seBytes)

	cs, err := counter.NewStore(cfg.CounterFile)
	if err != nil {
		return nil, "", nil, fmt.Errorf("could not create U2F counter store: %v", err)
	}

	return cfg, se, cs, nil
}

func (serv) Serve(cfg *server.Config, h http.Handler) error {
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
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: true,
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
	return server.ListenAndServeTLS("", "")
}

func main() {
	flag.Parse()
	if *configFile == "" {
		log.Fatalf("--config is required")
	}
	server.Run(serv{})
}
