package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"../alert"
	"../handler"
	"../session"
	"../static"

	"golang.org/x/crypto/acme/autocert"
)

const (
	debugU2FRegistration = "BQTh/D3Xi2VkWvc0mTicoUJeKnPnk3GgVla5JCvPcPhWkAtnCtAmW6bLIG9NHnZkNHUmKcmLTTlwvvs4Zfz+IKhbQAWYk1rzJYmMqdidWgaRlgmrDPL3gnPc1PATwUxUshRuuJVOvDqxvhzHMj4v3ziKs78obxZ4XFCVYTNZUPO+nnEwggJEMIIBLqADAgECAgRVYr6gMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTQzMjUzNDY4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEszH3c9gUS5mVy+RYVRfhdYOqR2I2lcvoWsSCyAGfLJuUZ64EWw5m8TGy6jJDyR/aYC4xjz/F2NKnq65yvRQwmjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMAsGCSqGSIb3DQEBCwOCAQEArBbZs262s6m3bXWUs09Z9Pc+28n96yk162tFHKv0HSXT5xYU10cmBMpypXjjI+23YARoXwXn0bm+BdtulED6xc/JMqbK+uhSmXcu2wJ4ICA81BQdPutvaizpnjlXgDJjq6uNbsSAp98IStLLp7fW13yUw+vAsWb5YFfK9f46Yx6iakM3YqNvvs9M9EUJYl/VrxBJqnyLx2iaZlnpr13o8NcsKIJRdMUOBqt/ageQg3ttsyq/3LyoNcu7CQ7x8NmeCGm/6eVnZMQjDmwFdymwEN4OxfnM5MkcKCYhjqgIGruWkVHsFnJa8qjZXneVvKoiepuUQyDEJ2GcqvhU2YKY1zBFAiB2afTDsR6rPnfYBSk6qpYf7UXUa9oXxPeJDMOuWHNlOAIhAIM14GSSI8rhLhWCMiFLEzD9T1G7SbfHS37fgGwyQgal"
)

var (
	configFile = flag.String("config", "", "The harpd configuration file to use.")
	debug      = flag.Bool("debug", false, "If set, serve over HTTP 8080 instead of HTTPS 443.")
)

// config stores a harpd server configuration.
type config struct {
	HostName            string   `json:"host_name"`          // The host name of the server.
	Email               string   `json:"email"`              // The email address of the server.
	CertDir             string   `json:"cert_dir"`           // The directory to use to store HTTPS certificates.
	PassDir             string   `json:"pass_dir"`           // The directory to use to store encrypted password files.
	KeyFile             string   `json:"key_file"`           // The location of the encrypted key file.
	CounterFile         string   `json:"counter_file"`       // The location of the U2F counter file.
	U2FRegistrations    []string `json:"u2f_regs"`           // The U2F registration blobs.
	AlertCmd            string   `json:"alert_cmd"`          // The command to run when an alert is sent.
	SessionDurationSecs float64  `json:"session_duration_s"` // The length of sessions, in seconds.
	NewSessionRate      float64  `json:"new_session_rate"`   // The rate that new sessions can be created, in Hz.
}

func main() {
	// Parse & sanity check flags.
	flag.Parse()
	if (*configFile == "" && !*debug) || (*configFile != "" && *debug) {
		log.Fatalf("Exactly one of --config and --debug must be set")
	}

	// Parse config & prepare session handler.
	var cfg *config
	var cs *session.CounterStore
	var se string
	if *debug {
		se = string(static.MustAsset("debug/key"))
		cs = session.NewMemoryCounterStore()

		passDir, err := ioutil.TempDir("", "harpd_debug_")
		if err != nil {
			log.Fatalf("Could not create temporary directory: %v", err)
		}
		log.Printf("Debug: serving passwords from %q", passDir)
		if err := static.RestoreAssets(passDir, "debug/passwords"); err != nil {
			log.Fatalf("Could not prepare password directory: %v", err)
		}
		cfg = &config{
			HostName:            "localhost:8080",
			PassDir:             filepath.Join(passDir, "debug/passwords"),
			U2FRegistrations:    []string{debugU2FRegistration},
			SessionDurationSecs: 300,
			NewSessionRate:      1,
		}
	} else {
		// Set a few sensible defaults and then read & parse the config.
		cfg = &config{
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
		// TODO: sanity-check config field values

		seBytes, err := ioutil.ReadFile(cfg.KeyFile)
		if err != nil {
			log.Fatalf("Could not read key file: %v", err)
		}
		se = string(seBytes)

		s, err := session.NewCounterStore(cfg.CounterFile)
		if err != nil {
			log.Fatalf("Could not create U2F counter store: %v", err)
		}
		cs = s
	}

	sessionDuration := time.Duration(cfg.SessionDurationSecs * float64(time.Second))
	var alerter alert.Alerter
	if cfg.AlertCmd != "" {
		alerter = alert.NewCommand(cfg.AlertCmd)
	} else {
		log.Printf("No alert_cmd specified, logging alerts")
		alerter = alert.NewLog()
	}

	sh, err := session.NewHandler(se, cfg.PassDir, cfg.HostName, cfg.U2FRegistrations, sessionDuration, cs, cfg.NewSessionRate, alerter)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}

	// Start serving.
	if *debug {
		certPEM := static.MustAsset("debug/cert.pem")
		keyPEM := static.MustAsset("debug/key.pem")
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Fatalf("Could not parse self-signed certificate: %v", err)
		}
		server := &http.Server{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			Addr:    "127.0.0.1:8080",
			Handler: handler.NewLogging("debug", handler.NewSecureHeader(handler.NewContent(sh))),
		}
		log.Printf("Serving debug")
		log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
	}

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
		Handler:      handler.NewLogging("https", handler.NewSecureHeader(handler.NewContent(sh))),
	}
	log.Printf("Serving")
	log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
}
