// rotate_key allows migrating between two different keys.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	kpb "github.com/BranLwyd/harpocrates/proto/key_proto"
	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/key"
	"github.com/golang/protobuf/proto"
)

var (
	inKeyFile   = flag.String("in_key", "", "Location of the input key.")
	inLocation  = flag.String("in_location", "", "Location of the input password entries.")
	outKeyFile  = flag.String("out_key", "", "Location of the output key.")
	outLocation = flag.String("out_location", "", "Location of the output password entries.")
)

func vault(location, keyFile string) (secret.Vault, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("could not read key file: %v", err)
	}
	k := &kpb.Key{}
	if err := proto.Unmarshal(keyBytes, k); err != nil {
		return nil, fmt.Errorf("could not unmarshal key: %v", err)
	}
	v, err := key.NewVault(location, k)
	if err != nil {
		return nil, fmt.Errorf("could not create vault: %v", err)
	}
	return v, nil
}

func main() {
	flag.Parse()
	if *inKeyFile == "" {
		log.Fatalf("--in_key is required")
	}
	if *inLocation == "" {
		log.Fatalf("--in_location is required")
	}
	if *outKeyFile == "" {
		log.Fatalf("--out_key is required")
	}
	if *outLocation == "" {
		log.Fatalf("--out_location is required")
	}

	// Create vaults.
	inVault, err := vault(*inLocation, *inKeyFile)
	if err != nil {
		log.Fatalf("Could not create `in` vault: %v", err)
	}
	outVault, err := vault(*outLocation, *outKeyFile)
	if err != nil {
		log.Fatalf("Could not create `out` vault: %v", err)
	}

	// Unlock vaults.
	passphrase := "password" // TODO(bran): allow custom passwords
	inStore, err := inVault.Unlock(passphrase)
	if err != nil {
		log.Fatalf("Could not create `in` store: %v", err)
	}
	outStore, err := outVault.Unlock(passphrase)
	if err != nil {
		log.Fatalf("Could not create `out` store: %v", err)
	}

	// Copy entries from `inStore` to `outStore`.
	es, err := inStore.List()
	if err != nil {
		log.Fatalf("Could not list `in` entries: %v", err)
	}
	for _, e := range es {
		log.Printf("Copying %q", e)
		content, err := inStore.Get(e)
		if err != nil {
			log.Fatalf("Could not get %q: %v", e, err)
		}
		if err := outStore.Put(e, content); err != nil {
			log.Fatalf("Could not put %q: %v", e, err)
		}
	}
}
