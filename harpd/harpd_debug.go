// +build debug

package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"

	"../handler"
	"../session"
	"../static"
)

const (
	debugU2FRegistration = "BQTh/D3Xi2VkWvc0mTicoUJeKnPnk3GgVla5JCvPcPhWkAtnCtAmW6bLIG9NHnZkNHUmKcmLTTlwvvs4Zfz+IKhbQAWYk1rzJYmMqdidWgaRlgmrDPL3gnPc1PATwUxUshRuuJVOvDqxvhzHMj4v3ziKs78obxZ4XFCVYTNZUPO+nnEwggJEMIIBLqADAgECAgRVYr6gMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTQzMjUzNDY4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEszH3c9gUS5mVy+RYVRfhdYOqR2I2lcvoWsSCyAGfLJuUZ64EWw5m8TGy6jJDyR/aYC4xjz/F2NKnq65yvRQwmjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMAsGCSqGSIb3DQEBCwOCAQEArBbZs262s6m3bXWUs09Z9Pc+28n96yk162tFHKv0HSXT5xYU10cmBMpypXjjI+23YARoXwXn0bm+BdtulED6xc/JMqbK+uhSmXcu2wJ4ICA81BQdPutvaizpnjlXgDJjq6uNbsSAp98IStLLp7fW13yUw+vAsWb5YFfK9f46Yx6iakM3YqNvvs9M9EUJYl/VrxBJqnyLx2iaZlnpr13o8NcsKIJRdMUOBqt/ageQg3ttsyq/3LyoNcu7CQ7x8NmeCGm/6eVnZMQjDmwFdymwEN4OxfnM5MkcKCYhjqgIGruWkVHsFnJa8qjZXneVvKoiepuUQyDEJ2GcqvhU2YKY1zBFAiB2afTDsR6rPnfYBSk6qpYf7UXUa9oXxPeJDMOuWHNlOAIhAIM14GSSI8rhLhWCMiFLEzD9T1G7SbfHS37fgGwyQgal"
)

func parseConfig() (_ *config, serializedEntity string, _ *session.CounterStore) {
	se := string(static.MustAsset("debug/key"))
	cs := session.NewMemoryCounterStore()

	passDir, err := ioutil.TempDir("", "harpd_debug_")
	if err != nil {
		log.Fatalf("Could not create temporary directory: %v", err)
	}
	log.Printf("Debug: serving passwords from %q", passDir)
	if err := static.RestoreAssets(passDir, "debug/passwords"); err != nil {
		log.Fatalf("Could not prepare password directory: %v", err)
	}
	cfg := &config{
		HostName:            "localhost:8080",
		PassDir:             filepath.Join(passDir, "debug/passwords"),
		U2FRegistrations:    []string{debugU2FRegistration},
		SessionDurationSecs: 300,
		NewSessionRate:      1,
	}

	return cfg, se, cs
}

func serve(_ *config, h http.Handler) {
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
		Handler: handler.NewLogging("debug", handler.NewSecureHeader(h)),
	}
	log.Printf("Serving debug on https://localhost:8080")
	log.Fatalf("Error while serving: %v", server.ListenAndServeTLS("", ""))
}
