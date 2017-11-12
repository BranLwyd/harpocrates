package main

import (
	"crypto/tls"
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

const (
	debugU2FRegistration = `BQSBXpTec0+pBxOno2+tZvspGT3kL2x5CGNGNjoIpI0wvlxxyhOXi4XCR3x4lF+o3Kl0g16cffetBRF+ApH/fFa2QBCXlXW+fatptZnZyvULE8spyD4h+lgazjNuJjOv/Jgsy7Zbmbk5Uceoacxc0NFlCMFADvT73eUuyYtCwMp03iUwggJKMIIBMqADAgECAgRXFvfAMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAsMSowKAYDVQQDDCFZdWJpY28gVTJGIEVFIFNlcmlhbCAyNTA1NjkyMjYxNzYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARk2RxU1tlXjdOwYHhMRjbVSKOYOq81J87rLcbjK2eeM/zp6GMUrbz4V1IbL0xJn5SvcFVlviIZWym2Tk2tDdBiozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNTATBgsrBgEEAYLlHAIBAQQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAeJsYypuk23Yg4viLjP3pUSZtKiJ31eP76baMmqDpGmpI6nVM7wveWYQDba5/i6P95ktRdgTDoRsubXVNSjcZ76h2kw+g4PMGP1pMoLygMU9/BaPqXU7dkdNKZrVdXI+obgDnv1/dgCN+s9uCPjTjEmezSarHnCSnEqWegEqqjWupJSaid6dx3jFqc788cR/FTSJmJ/rXleT0ThtwA08J/P44t94peJP7WayLHDPPxca+XY5Mwn9KH0b2+ET4eMByi9wd+6Zx2hCH9Yzjjllro/Kf0FlBXcUKoy+JFHzT2wgBN9TmW7zrC7/lQYgYjswUMRh5UZKrOnOHqaVyfxBIhjBEAiAf9Ct62olZrM9/3zYrAtZJp2UA2ez47O2cg294x15CUwIgQPcLJ0i4iORmJdKR9WdJS1xw7HP/Gcjj1xCll1gGK4w`
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
	cfg := &server.Config{
		HostName:            "localhost:8080",
		PassDir:             filepath.Join(passDir, "debug/passwords"),
		U2FRegistrations:    []string{debugU2FRegistration},
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
