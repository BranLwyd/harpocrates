package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/BranLwyd/harpocrates/counter"
	"github.com/BranLwyd/harpocrates/handler"
	"github.com/BranLwyd/harpocrates/server"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/acme/autocert"

	cpb "github.com/BranLwyd/harpocrates/proto/config_go_proto"
	kpb "github.com/BranLwyd/harpocrates/proto/key_go_proto"
)

var (
	configFile = flag.String("config", "", "The harpd configuration file to use.")
)

// serv implements server.Server.
type serv struct{}

func (serv) ParseConfig() (_ *cpb.Config, _ *kpb.Key, _ *counter.Store, _ error) {
	// Read & parse the config.
	cfgBytes, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not read config file: %v", err)
	}
	cfg := &cpb.Config{}
	if err := proto.UnmarshalText(string(cfgBytes), cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse config file: %v", err)
	}

	// Fill in sesnsible defaults for some fields if needed.
	if cfg.SessionDurationS == 0 {
		cfg.SessionDurationS = 300
	}
	if cfg.NewSessionRate == 0 {
		cfg.NewSessionRate = 1
	}

	// Sanity check config values.
	if cfg.HostName == "" {
		return nil, nil, nil, errors.New("host_name is required in config")
	}
	if cfg.Email == "" {
		return nil, nil, nil, errors.New("email is required in config")
	}
	if cfg.CertDir == "" {
		return nil, nil, nil, errors.New("cert_dir is required in config")
	}
	if cfg.PassLoc == "" {
		return nil, nil, nil, errors.New("pass_loc is required in config")
	}
	if cfg.KeyFile == "" {
		return nil, nil, nil, errors.New("key_file is required in config")
	}
	if cfg.CounterFile == "" {
		return nil, nil, nil, errors.New("counter_file is required in config")
	}
	if cfg.SessionDurationS <= 0 {
		return nil, nil, nil, errors.New("session_duration_s must be positive")
	}
	if cfg.NewSessionRate <= 0 {
		return nil, nil, nil, errors.New("new_session_rate must be positive")
	}

	if cfg.AlertCmd == "" {
		log.Printf("No alert_cmd specified, logging alerts")
	}

	// Create key, counter store based on config.
	keyBytes, err := ioutil.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not read key file: %v", err)
	}
	k := &kpb.Key{}
	if err := proto.Unmarshal(keyBytes, k); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse key: %v", err)
	}

	cs, err := counter.NewStore(cfg.CounterFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not create U2F counter store: %v", err)
	}

	return cfg, k, cs, nil
}

func (serv) Serve(cfg *cpb.Config, h http.Handler) error {
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
				tls.X25519,
				tls.CurveP256,
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
	// Serve HTTP redirects & ACME challenge traffic...
	go serveHTTPRedirects(m.HTTPHandler(nil))

	// ..and serve content on HTTPS.
	return server.ListenAndServeTLS("", "")
}

func serveHTTPRedirects(h http.Handler) {
	server := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      h,
	}
	log.Fatalf("ListenAndServe: %v", server.ListenAndServe())
}

func main() {
	flag.Parse()
	if *configFile == "" {
		log.Fatalf("--config is required")
	}
	server.Run(serv{})
}
