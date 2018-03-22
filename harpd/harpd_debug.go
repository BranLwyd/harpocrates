package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/BranLwyd/harpocrates/harpd/counter"
	"github.com/BranLwyd/harpocrates/harpd/debug_assets"
	"github.com/BranLwyd/harpocrates/harpd/handler"
	"github.com/BranLwyd/harpocrates/harpd/server"
	"github.com/golang/protobuf/proto"

	cpb "github.com/BranLwyd/harpocrates/harpd/proto/config_go_proto"
	pb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
)

var (
	u2f        = flag.String("u2f", "", "If specified, the U2F key to use.")
	hostname   = flag.String("hostname", "", "The hostname to serve with. Defaults to os.Hostname().")
	encryption = flag.String("encryption", "harp", "The type of encryption to use. Valid options include `harp` and `pgp`.")
)

// serv implements server.Server.
type serv struct{}

func (serv) ParseConfig() (_ *cpb.Config, _ *pb.Key, _ *counter.Store, _ error) {
	keyBytes := debug_assets.MustAsset(fmt.Sprintf("debug/key.%s", *encryption))
	k := &pb.Key{}
	if err := proto.Unmarshal(keyBytes, k); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse key: %v", err)
	}

	cs := counter.NewMemoryStore()

	passDir, err := ioutil.TempDir("", "harpd_debug_")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not create temporary directory: %v", err)
	}
	log.Printf("Debug mode: serving passwords from %q", passDir)
	if err := debug_assets.RestoreAssets(passDir, fmt.Sprintf("debug/passwords.%s", *encryption)); err != nil {
		return nil, nil, nil, fmt.Errorf("could not prepare password directory: %v", err)
	}
	var u2fRegs []string
	if *u2f != "" {
		u2fRegs = []string{*u2f}
	} else {
		log.Printf("No U2F registration specified. Navigate to https://%s:8080/register to register a token, then specify it via --u2f.", *hostname)
	}
	cfg := &cpb.Config{
		HostName:         fmt.Sprintf("%s:8080", *hostname),
		PassLoc:          filepath.Join(passDir, fmt.Sprintf("debug/passwords.%s", *encryption)),
		U2FReg:           u2fRegs,
		SessionDurationS: 300,
		NewSessionRate:   1,
	}
	return cfg, k, cs, nil
}

func (serv) Serve(_ *cpb.Config, h http.Handler) error {
	// Generate a self-signed certificate with the appropriate hostname.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate key: %v", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Harpocrates"},
		},
		DNSNames:              []string{*hostname},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// Begin serving.
	server := &http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{certDER},
				PrivateKey:  priv,
				Leaf:        cert,
			}},
		},
		Addr:    ":8080",
		Handler: handler.NewLogging("debug", handler.NewSecureHeader(h)),
	}
	log.Printf(`Serving debug on https://%s:8080 [the password is "password"]`, *hostname)
	return server.ListenAndServeTLS("", "")
}

func main() {
	flag.Parse()
	if *hostname == "" {
		hn, err := os.Hostname()
		if err != nil {
			*hostname = "localhost"
			log.Printf("Could not get hostname (defaulting to %q, override with --hostname): %v", *hostname, err)
		} else {
			*hostname = hn
			log.Printf("Defaulting hostname to %q (override with --hostname)", hn)
		}
	}
	server.Run(serv{})
}
