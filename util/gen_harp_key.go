// gen_harp_key generates a native Harpocrates key.
package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/scrypt"

	kpb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

var (
	out     = flag.String("out", "", "Location to write key.")
	scryptN = flag.Int("N", 32768, "Scrypt `N` value. Must be a power of 2 greater than 1.")
	scryptR = flag.Int("r", 8, "Scrypt `r` value. Must satisfy r * p < 2^30.")
	scryptP = flag.Int("p", 1, "Scrypt `p` value. Must satisfy r * p < 2^30.")
)

func main() {
	flag.Parse()
	if *out == "" {
		log.Fatalf("--out is required")
	}

	// Generate EK.
	var ek [32]byte
	if _, err := rand.Read(ek[:]); err != nil {
		log.Fatalf("Could not generate EK: %v", err)
	}

	// Derive KEK.
	password := []byte("password") // TODO(bran): allow custom passwords
	salt := []byte("harpocrates_key_        ")
	if _, err := rand.Read(salt[len("harpocrates_key_"):]); err != nil {
		log.Fatalf("Could not generate random salt: %v", err)
	}
	kek, err := scrypt.Key(password, salt, *scryptN, *scryptR, *scryptP, 32)
	if err != nil {
		log.Fatalf("Could not derive KEK: %v", err)
	}

	// Generate key proto & write to disk.
	kekBlk, err := aes.NewCipher(kek)
	if err != nil {
		log.Fatalf("Could not create block cipher for KEK: %v", err)
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
		log.Fatalf("Could not marshal key: %v", err)
	}
	if err := ioutil.WriteFile(*out, keyBytes, 0400); err != nil {
		log.Fatalf("Could not write key: %v", err)
	}
}
