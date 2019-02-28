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
		fmt.Printf("%s: could not read keyfile: %v\n", kf, err)
		return
	}
	key := &kpb.Key{}
	if err := proto.Unmarshal(keyBytes, key); err != nil {
		fmt.Printf("%s: could not parse keyfile: %v\n", kf, err)
		return
	}

	switch k := key.Key.(type) {
	case *kpb.Key_PgpKey:
		fmt.Printf("%s: PGP key\n", kf)
		// TODO: more detail?
	case *kpb.Key_HarpKey:
		fmt.Printf("%s: Harpocrates-native key\n", kf)
		fmt.Printf("Parameters: N = %d, r = %d, p = %d\n", k.HarpKey.N, k.HarpKey.R, k.HarpKey.P)
	case *kpb.Key_SecretboxKey:
		fmt.Printf("%s: Secretbox key\n", kf)
		fmt.Printf("Parameters: N = %d, r = %d, p = %d\n", k.SecretboxKey.N, k.SecretboxKey.R, k.SecretboxKey.P)
	case nil:
		fmt.Printf("%s: could not parse keyfile: no key\n", kf)
	default:
		fmt.Printf("%s: unknown key type\n", kf)
	}
}
