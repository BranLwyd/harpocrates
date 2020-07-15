package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"

	kpb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
)

func dieWithUsage(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n\n", a...)
	flag.Usage()
	os.Exit(1)
}

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	// Parse and verify flags.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] keyfile keyfile ...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	kfs := flag.Args()
	switch {
	case len(kfs) == 0:
		dieWithUsage("At lest one keyfile is required.")
	}

	for i, kf := range kfs {
		describeKey(kf)
		if i != len(kfs)-1 {
			fmt.Println()
		}
	}
}

func describeKey(kf string) {
	keyBytes, err := ioutil.ReadFile(kf)
	if err != nil {
		die("%s: couldn't read keyfile: %v", kf, err)
		return
	}
	key := &kpb.Key{}
	if err := proto.Unmarshal(keyBytes, key); err != nil {
		die("%s: couldn't parse keyfile: %v", kf, err)
		return
	}

	switch k := key.Key.(type) {
	case *kpb.Key_PgpKey:
		fmt.Printf("%s: PGP key\n", kf)
		// TODO: more detail?
	case *kpb.Key_SecretboxKey:
		fmt.Printf("%s: Secretbox key\n", kf)
		fmt.Printf("Parameters: N = %d, r = %d, p = %d\n", k.SecretboxKey.N, k.SecretboxKey.R, k.SecretboxKey.P)
	case nil:
		die("%s: couldn't parse keyfile: no key", kf)
	default:
		die("%s: unknown key type", kf)
	}
}
