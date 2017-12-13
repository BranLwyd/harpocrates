// wrap_serialized_pgp_entity wraps a serialzed PGP entity into a Harpocrates key.
//
// Example usage:
//  $ pgp --export-secret-key "key identity" >serialized_entity
//  $ wrap_serialized_pgp_entity --in=serialized_entity --out=key
package main

import (
	"flag"
	"io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"

	pb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

var (
	inFile  = flag.String("in", "", "Location to read serialized PGP entity.")
	outFile = flag.String("out", "", "Location to write harpocrates key.")
)

func main() {
	flag.Parse()
	if *inFile == "" {
		log.Fatalf("--in is required")
	}
	if *outFile == "" {
		log.Fatalf("--out is required")
	}

	se, err := ioutil.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("Could not read %q: %v", *inFile, err)
	}
	keyBytes, err := proto.Marshal(&pb.Key{
		Key: &pb.Key_PgpKey{&pb.PGPKey{
			SerializedEntity: se,
		}},
	})
	if err != nil {
		log.Fatalf("Could not serialize key: %v", err)
	}
	if err := ioutil.WriteFile(*outFile, keyBytes, 0600); err != nil {
		log.Fatalf("Could not write serialized key: %v", err)
	}
}
