// gen_pgp_key generates a Harpocrates PGP key by wrapping a serialzed PGP entity into a Harpocrates key.
//
// Example usage:
//   [generate a private key suing standard PGP tools]
//  $ pgp --export-secret-key "key identity" >serialized_entity
//  $ wrap_serialized_pgp_entity --in=serialized_entity --out=key
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"

	pb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

var (
	out    = flag.String("out", "", "Location to write harpocrates key.")
	seFile = flag.String("serialized_entity", "", "Location of serialized PGP entity.")
)

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprintln(os.Stderr, "")
	os.Exit(1)
}

func main() {
	flag.Parse()
	if *seFile == "" {
		die("--serialized_entity is required")
	}
	if *out == "" {
		die("--out is required")
	}

	se, err := ioutil.ReadFile(*seFile)
	if err != nil {
		die("Could not read %q: %v", *seFile, err)
	}
	keyBytes, err := proto.Marshal(&pb.Key{
		Key: &pb.Key_PgpKey{&pb.PGPKey{
			SerializedEntity: se,
		}},
	})
	if err != nil {
		die("Could not marshal key: %v", err)
	}
	if err := ioutil.WriteFile(*out, keyBytes, 0400); err != nil {
		die("Could not write key: %v", err)
	}
}
