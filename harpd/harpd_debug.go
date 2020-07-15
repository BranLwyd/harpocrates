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
	"strings"
	"time"

	"github.com/BranLwyd/harpocrates/harpd/debug_assets"
	"github.com/BranLwyd/harpocrates/harpd/handler"
	"github.com/BranLwyd/harpocrates/harpd/server"
	"github.com/golang/protobuf/proto"

	cpb "github.com/BranLwyd/harpocrates/harpd/proto/config_go_proto"
	pb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
)

var (
	mfa        = flag.String("mfa", "", "If specified, the MFA key to use.")
	hostname   = flag.String("hostname", "", "The hostname to serve with. Defaults to os.Hostname().")
	encryption = flag.String("encryption", "sbox", "The type of encryption to use. Valid options include `sbox` and `pgp`.")
)

// serv implements server.Server.
type serv struct{}

func (serv) ParseConfig() (_ *cpb.Config, _ *pb.Key, _ error) {
	keyBytes := mustAsset(fmt.Sprintf("harpd/assets/debug/key.%s", *encryption))
	k := &pb.Key{}
	if err := proto.Unmarshal(keyBytes, k); err != nil {
		return nil, nil, fmt.Errorf("could not parse key: %w", err)
	}

	passDir, err := ioutil.TempDir("", "harpd_debug_")
	if err != nil {
		return nil, nil, fmt.Errorf("could not create temporary directory: %w", err)
	}
	log.Printf("Debug mode: serving passwords from %q", passDir)
	if err := restoreAssets(passDir, fmt.Sprintf("harpd/assets/debug/passwords.%s", *encryption)); err != nil {
		return nil, nil, fmt.Errorf("could not prepare password directory: %w", err)
	}
	var mfaRegs []string
	if *mfa != "" {
		mfaRegs = []string{*mfa}
	} else {
		log.Printf("No MFA registration specified. Navigate to https://%s:8080/register to register a token, then specify it via --mfa.", *hostname)
	}
	cfg := &cpb.Config{
		HostName:         fmt.Sprintf("%s:8080", *hostname),
		PassLoc:          filepath.Join(passDir, fmt.Sprintf("harpd/assets/debug/passwords.%s", *encryption)),
		MfaReg:           mfaRegs,
		SessionDurationS: 300,
		NewSessionRate:   1,
	}
	return cfg, k, nil
}

func (serv) Serve(_ *cpb.Config, h http.Handler) error {
	// Generate a self-signed certificate with the appropriate hostname.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("could not generate key: %w", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
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
		return fmt.Errorf("failed to create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Begin serving.
	server := &http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{certDER},
				PrivateKey:  priv,
				Leaf:        cert,
			}},
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: true,
		},
		Addr:    ":8080",
		Handler: handler.NewLogging("debug", handler.NewSecureHeader(h)),
	}
	log.Printf(`Serving debug on https://%s:8080 [the password is "password"]`, *hostname)
	return server.ListenAndServeTLS("", "")
}

func mustAsset(name string) []byte {
	a, ok := debug_assets.Asset[name]
	if !ok {
		panic(fmt.Sprintf("Debug asset %q does not exist", name))
	}
	return a
}

func restoreAssets(dst, src string) error {
	for name, val := range debug_assets.Asset {
		if !strings.HasPrefix(name, src) {
			continue
		}
		fn := filepath.Join(dst, name)
		pth := filepath.Dir(fn)
		if err := os.MkdirAll(pth, 0755); err != nil {
			return fmt.Errorf("could not create %q: %w", pth, err)
		}
		if err := ioutil.WriteFile(fn, val, 0644); err != nil {
			return fmt.Errorf("could not write %q: %w", fn, err)
		}
	}
	return nil
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
