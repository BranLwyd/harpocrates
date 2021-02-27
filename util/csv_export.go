// csv_export exports a vault to an UNENCRYPTED CSV file.
// It is developed for use with 1Password's import feature, but is likely generally useful.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/key"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ssh/terminal"

	kpb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
)

var (
	inKeyFile   = flag.String("in_key", "", "Location of the input key.")
	inLocation  = flag.String("in_location", "", "Location of the input password entries.")
	outLocation = flag.String("out_location", "", "Location of the output CSV file.")
)

func main() {
	// Parse & validate flags.
	flag.Parse()
	if *inKeyFile == "" {
		die("--in_key is required")
	}
	if *inLocation == "" {
		die("--in_location is required")
	}
	if *outLocation == "" {
		die("--out_location is required")
	}

	// Create & unlock vault.
	v, err := vault(*inLocation, *inKeyFile)
	if err != nil {
		die("Couldn't create vault: %v", err)
	}
	fmt.Printf("Passphrase: ")
	inPass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		die("Could not get passphrase: %v", err)
	}
	s, err := v.Unlock(string(inPass))
	if err != nil {
		die("Could not open vault: %v", err)
	}

	// Write entries to CSV file.
	f, err := os.Create(*outLocation)
	if err != nil {
		die("Couldn't create CSV file: %v", err)
	}
	defer f.Close()
	cw := csv.NewWriter(f)

	es, err := s.List()
	if err != nil {
		die("Couldn't list entries in password store: %v", err)
	}
	for _, e := range es {
		content, err := s.Get(e)
		if err != nil {
			die("Couldn't get content of %q: %v", e, err)
		}
		if err := cw.Write(record(e, content)); err != nil {
			die("Couldn't write content of %q: %v", e, err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		die("Couldn't ")
	}
}

func record(entry, content string) []string {
	lines := strings.Split(content, "\n")
	rec := append([]string{entry}, lines...)

	// Remove any trailing empty lines.
	for len(rec) > 0 && rec[len(rec)-1] == "" {
		rec = rec[:len(rec)-1]
	}

	return rec
}

func vault(location, keyFile string) (secret.Vault, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read key file: %w", err)
	}
	k := &kpb.Key{}
	if err := proto.Unmarshal(keyBytes, k); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal key: %w", err)
	}
	v, err := key.NewVault(location, k)
	if err != nil {
		return nil, fmt.Errorf("couldn't create vault: %w", err)
	}
	return v, nil
}

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
