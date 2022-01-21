package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/key"
	kpb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	keyFile  = flag.String("key", "", "Location of the input key.")
	location = flag.String("location", "", "Location of the input password entries.")
	entry    = flag.String("entry", "", "The entry to read.")
)

func main() {
	// Parse & validate flags.
	flag.Parse()
	if *keyFile == "" {
		die("--key is required")
	}
	if *location == "" {
		die("--location is required")
	}
	if *entry == "" {
		die("--entry is required")
	}

	// Create vault.
	v, err := vault(*location, *keyFile)
	if err != nil {
		die("Could not initialize vault: %v", err)
	}

	// Unlock vault.
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

	// Read & print the requested entry.
	entryContent, err := s.Get(*entry)
	if err != nil {
		die("Couldn't get entry %q: %v", *entry, err)
	}
	fmt.Printf("%s\n", entryContent)
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
