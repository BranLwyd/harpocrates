// Package harp provides a simple interface to interact with Harpocrates-native
// password stores. It is efficient & secure, but not compatible with other
// password managers.
package harp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/file"
	"github.com/BranLwyd/harpocrates/secret/key_private"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/scrypt"

	epb "github.com/BranLwyd/harpocrates/proto/entry_proto"
	kpb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

func init() {
	key_private.RegisterVaultFromKeyFunc(func(location string, key *kpb.Key) (secret.Vault, error) {
		if k := key.GetHarpKey(); k != nil {
			// TODO(bran): validate fields
			return &vault{
				baseDir:     location,
				encryptedEK: k.EncryptedKey,
				salt:        k.Salt,
				n:           int(k.N),
				r:           int(k.R),
				p:           int(k.P),
				kekHash:     k.KekSha256,
			}, nil
		}
		return nil, nil
	})
}

// vault implements secret.Vault.
type vault struct {
	baseDir string

	// Encrypted encryption key (EK).
	encryptedEK []byte

	// Scrypt parameters for the key-encryption key (KEK).
	salt    []byte
	n, r, p int
	kekHash []byte
}

func (v *vault) Unlock(passphrase string) (secret.Store, error) {
	// Derive the KEK from the passphrase and the given paramemters.
	kek, err := scrypt.Key([]byte(passphrase), v.salt, v.n, v.r, v.p, 32)
	if err != nil {
		return nil, fmt.Errorf("could not derive key-encryption key: %v", err)
	}

	// Check the KEK.
	// (It might be seen as preferable to simply encrypt the EK with an AEAD; but Go's
	// AES-GCM implementation isn't constant-time on many platforms.)
	if kekHash := sha256.Sum256(kek); subtle.ConstantTimeCompare(kekHash[:], v.kekHash) != 1 {
		return nil, secret.ErrWrongPassphrase
	}

	// Use the KEK to decrypt the EK.
	kekBlk, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("could not create block cipher for key-encryption key: %v", err)
	}
	ek := make([]byte, len(v.encryptedEK))
	kekBlk.Decrypt(ek, v.encryptedEK)

	// Return a file store based on this key.
	ekBlk, err := aes.NewCipher(ek)
	if err != nil {
		return nil, fmt.Errorf("could not create block cipher for encryption key: %v", err)
	}
	ekGCM, err := cipher.NewGCM(ekBlk)
	if err != nil {
		return nil, fmt.Errorf("could not build AEAD: %v", err)
	}
	return file.NewStore(v.baseDir, ".harp", crypter{ekGCM}), nil
}

type crypter struct {
	c cipher.AEAD
}

func (c crypter) Encrypt(entryName, content string) (ciphertext []byte, _ error) {
	nonce := make([]byte, c.c.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("could not generate nonce: %v", err)
	}
	encryptedContent := c.c.Seal(nil, nonce, []byte(content), []byte(entryName))
	ciphertext, err := proto.Marshal(&epb.Entry{
		EncryptedContent: encryptedContent,
		Nonce:            nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("could not marshal entry: %v", err)
	}
	return ciphertext, nil
}

func (c crypter) Decrypt(entryName string, ciphertext []byte) (content string, _ error) {
	entry := &epb.Entry{}
	if err := proto.Unmarshal(ciphertext, entry); err != nil {
		return "", fmt.Errorf("could not unmarshal entry: %v", err)
	}
	contentBytes, err := c.c.Open(nil, entry.Nonce, entry.EncryptedContent, []byte(entryName))
	if err != nil {
		return "", fmt.Errorf("could not decrypt: %v", err)
	}
	return string(contentBytes), nil
}
