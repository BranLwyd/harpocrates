// gen_harp_key generates a native Harpocrates key.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/scrypt"

	kpb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

var (
	out     = flag.String("out", "", "Location to write key.")
	scryptN = flag.Int("N", 32768, "Scrypt `N` value. Must be a power of 2 greater than 1.")
	scryptR = flag.Int("r", 8, "Scrypt `r` value. Must satisfy r * p < 2^30.")
	scryptP = flag.Int("p", 1, "Scrypt `p` value. Must satisfy r * p < 2^30.")
)

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprintln(os.Stderr, "")
	os.Exit(1)
}

func main() {
	flag.Parse()
	if *out == "" {
		die("--out is required")
	}

	// Get passphrase from user.
	fmt.Printf("Passphrase: ")
	passphrase, err := gopass.GetPasswd()
	if err != nil {
		die("Could not get passphrase: %v", err)
	}
	fmt.Printf("Enter it again: ")
	secondTry, err := gopass.GetPasswd()
	if err != nil {
		die("Could not get passphrase: %v", err)
	}
	if !bytes.Equal(passphrase, secondTry) {
		die("Passphrases don't match.")
	}

	// Generate EK.
	var ek [32]byte
	if _, err := rand.Read(ek[:]); err != nil {
		die("Could not generate EK: %v", err)
	}

	// Derive KEK from passphrase.
	salt := []byte("harpocrates_key_        ")
	if _, err := rand.Read(salt[len("harpocrates_key_"):]); err != nil {
		die("Could not generate random salt: %v", err)
	}
	kek, err := scrypt.Key(passphrase, salt, *scryptN, *scryptR, *scryptP, 32)
	if err != nil {
		die("Could not derive KEK: %v", err)
	}

	// Generate key proto & write to disk.
	kekBlk, err := aes.NewCipher(kek)
	if err != nil {
		die("Could not create block cipher for KEK: %v", err)
	}
	kekBlk.Encrypt(ek[:], ek[:])
	kekHash := sha256.Sum256(kek)

	keyBytes, err := proto.Marshal(&kpb.Key{
		Key: &kpb.Key_HarpKey{&kpb.HarpKey{
			EncryptedKey: ek[:],
			Salt:         salt,
			N:            int32(*scryptN),
			R:            int32(*scryptR),
			P:            int32(*scryptP),
			KekSha256:    kekHash[:],
		}},
	})
	if err != nil {
		die("Could not marshal key: %v", err)
	}
	if err := ioutil.WriteFile(*out, keyBytes, 0400); err != nil {
		die("Could not write key: %v", err)
	}
}
