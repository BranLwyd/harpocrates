// gen_harp_key generates a native Harpocrates secretbox key.
package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"

	kpb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
)

var (
	out     = flag.String("out", "", "Location to write key.")
	scryptN = flag.Int("N", 32768, "Scrypt `N` value. Must be a power of 2 greater than 1.")
	scryptR = flag.Int("r", 8, "Scrypt `r` value. Must satisfy r * p < 2^30.")
	scryptP = flag.Int("p", 1, "Scrypt `p` value. Must satisfy r * p < 2^30.")
)

const (
	keySize   = 32
	nonceSize = 24
)

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	flag.Parse()
	if *out == "" {
		die("--out is required")
	}

	// Get passphrase from user.
	fmt.Printf("Passphrase: ")
	passphrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		die("Could not get passphrase: %v", err)
	}
	fmt.Printf("Enter it again: ")
	secondTry, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		die("Could not get passphrase: %v", err)
	}
	if !bytes.Equal(passphrase, secondTry) {
		die("Passphrases don't match.")
	}

	// Generate EK & EK-encryption nonce.
	var ek [keySize]byte
	if _, err := rand.Read(ek[:]); err != nil {
		die("Could not generate EK: %v", err)
	}
	var eekNonce [nonceSize]byte
	if _, err := rand.Read(eekNonce[:]); err != nil {
		die("Could not generate nonce: %v", err)
	}

	// Derive KEK from passphrase.
	salt := []byte("harpocrates_key_        ")
	if _, err := rand.Read(salt[len("harpocrates_key_"):]); err != nil {
		die("Could not generate salt: %v", err)
	}
	kekBuf, err := scrypt.Key(passphrase, salt, *scryptN, *scryptR, *scryptP, keySize)
	if err != nil {
		die("Could not derive KEK: %v", err)
	}
	var kek [keySize]byte
	copy(kek[:], kekBuf)

	// Generate key proto & write to disk.
	keyBytes, err := proto.Marshal(&kpb.Key{
		Key: &kpb.Key_SecretboxKey{&kpb.SecretboxKey{
			EncryptedKey:      secretbox.Seal(nil, ek[:], &eekNonce, &kek),
			EncryptedKeyNonce: eekNonce[:],
			Salt:              salt,
			N:                 int32(*scryptN),
			R:                 int32(*scryptR),
			P:                 int32(*scryptP),
		}},
	})
	if err != nil {
		die("Could not marshal key: %v", err)
	}
	if err := ioutil.WriteFile(*out, keyBytes, 0400); err != nil {
		die("Could not write key: %v", err)
	}
}
