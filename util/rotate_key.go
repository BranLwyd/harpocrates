// rotate_key allows migrating between two different keys.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/key"
	"github.com/golang/protobuf/proto"
	"github.com/howeyc/gopass"

	kpb "github.com/BranLwyd/harpocrates/proto/key_go_proto"
)

var (
	inKeyFile   = flag.String("in_key", "", "Location of the input key.")
	inLocation  = flag.String("in_location", "", "Location of the input password entries.")
	outKeyFile  = flag.String("out_key", "", "Location of the output key.")
	outLocation = flag.String("out_location", "", "Location of the output password entries.")
)

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprintln(os.Stderr, "")
	os.Exit(1)
}

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
		die("--in_key is required")
	}
	if *inLocation == "" {
		die("--in_location is required")
	}
	if *outKeyFile == "" {
		die("--out_key is required")
	}
	if *outLocation == "" {
		die("--out_location is required")
	}

	// Create vaults.
	inVault, err := vault(*inLocation, *inKeyFile)
	if err != nil {
		die("Could not initialize `in` vault: %v", err)
	}
	outVault, err := vault(*outLocation, *outKeyFile)
	if err != nil {
		die("Could not initialize `out` vault: %v", err)
	}

	// Unlock vaults.
	fmt.Printf("Passphrase for `in` key: ")
	inPass, err := gopass.GetPasswd()
	if err != nil {
		die("Could not get passphrase: %v", err)
	}
	inStore, err := inVault.Unlock(string(inPass))
	if err != nil {
		die("Could not open `in` vault: %v", err)
	}
	fmt.Printf("Passphrase for `out` key: ")
	outPass, err := gopass.GetPasswd()
	if err != nil {
		die("Could not get passphrase: %v", err)
	}
	outStore, err := outVault.Unlock(string(outPass))
	if err != nil {
		die("Could not open `out` vault: %v", err)
	}

	// Copy entries from `inStore` to `outStore`.
	es, err := inStore.List()
	if err != nil {
		die("Could not list entries in `in` vault: %v", err)
	}
	for _, e := range es {
		fmt.Printf("Copying %s\n", e)
		content, err := inStore.Get(e)
		if err != nil {
			die("Could not get %q: %v", e, err)
		}
		if err := outStore.Put(e, content); err != nil {
			die("Could not put %q: %v", e, err)
		}
	}
}
