package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"

	"github.com/BranLwyd/harpocrates/counter"
	"github.com/BranLwyd/harpocrates/debug_assets"
	"github.com/BranLwyd/harpocrates/handler"
	"github.com/BranLwyd/harpocrates/server"
)

var (
	u2f = flag.String("u2f", "", "If specified, the U2F key to use.")
)

// serv implements server.Server.
type serv struct{}

func (serv) ParseConfig() (_ *server.Config, serializedEntity string, _ *counter.Store, _ error) {
	se := string(debug_assets.MustAsset("debug/key"))
	cs := counter.NewMemoryStore()

	passDir, err := ioutil.TempDir("", "harpd_debug_")
	if err != nil {
		return nil, "", nil, fmt.Errorf("could not create temporary directory: %v", err)
	}
	log.Printf("Debug: serving passwords from %q", passDir)
	if err := debug_assets.RestoreAssets(passDir, "debug/passwords"); err != nil {
		return nil, "", nil, fmt.Errorf("could not prepare password directory: %v", err)
	}
	var u2fRegs []string
	if *u2f != "" {
		u2fRegs = []string{*u2f}
	} else {
		log.Printf("No U2F registration specified. Navigate to https://localhost:8080/register to register a token, then specify it via --u2f.")
	}
	cfg := &server.Config{
		HostName:            "localhost:8080",
		PassDir:             filepath.Join(passDir, "debug/passwords"),
		U2FRegistrations:    u2fRegs,
		SessionDurationSecs: 300,
		NewSessionRate:      1,
	}
	return cfg, se, cs, nil
}

func (serv) Serve(_ *server.Config, h http.Handler) error {
	certPEM := debug_assets.MustAsset("debug/cert.pem")
	keyPEM := debug_assets.MustAsset("debug/key.pem")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Could not parse self-signed certificate: %v", err)
	}
	server := &http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		Addr:    "127.0.0.1:8080",
		Handler: handler.NewLogging("debug", handler.NewSecureHeader(h)),
	}
	log.Printf("Serving debug on https://localhost:8080")
	return server.ListenAndServeTLS("", "")
}

func main() {
	server.Run(serv{})
}
