// Package secretbox provides an encryption scheme based on the NaCl secretbox
// primitives. It is efficient & secure, but not compatible with other password
// managers.
//
// https://nacl.cr.yp.to/secretbox.html
package secretbox

import (
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/file"
	"github.com/BranLwyd/harpocrates/secret/key_private"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	epb "github.com/BranLwyd/harpocrates/secret/proto/entry_go_proto"
	kpb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
)

func init() {
	key_private.RegisterVaultFromKeyFunc(func(location string, key *kpb.Key) (secret.Vault, error) {
		if k := key.GetSecretboxKey(); k != nil {
			switch {
			case len(k.EncryptedKey) != keySize+secretbox.Overhead:
				return nil, errors.New("unexpected size for encrypted_key")
			case len(k.EncryptedKeyNonce) != nonceSize:
				return nil, errors.New("unexpected size for encrypted_key_nonce")
			}

			v := &vault{
				baseDir: filepath.Clean(location),
				salt:    k.Salt,
				n:       int(k.N),
				r:       int(k.R),
				p:       int(k.P),
			}
			copy(v.encryptedEK[:], k.EncryptedKey)
			copy(v.eekNonce[:], k.EncryptedKeyNonce)
			return v, nil
		}
		return nil, nil
	})
}

const (
	keySize   = 32
	nonceSize = 24
)

type vault struct {
	baseDir string

	// Encrypted encryption key (EK), & nonce used to encrypt it.
	encryptedEK [keySize + secretbox.Overhead]byte
	eekNonce    [nonceSize]byte

	// Scrypt parameters for the key-encryption key (KEK).
	salt    []byte
	n, r, p int
}

func (v *vault) Unlock(passphrase string) (secret.Store, error) {
	// Derive the KEK from the passphrase and the given paramemters.
	var kek [keySize]byte
	kekBuf, err := scrypt.Key([]byte(passphrase), v.salt, v.n, v.r, v.p, keySize)
	if err != nil {
		return nil, fmt.Errorf("could not derive key-encryption key: %w", err)
	}
	copy(kek[:], kekBuf)

	// Decrypt the EK using the derived KEK.
	var ek [keySize]byte
	ekBuf, ok := secretbox.Open(nil, v.encryptedEK[:], &v.eekNonce, &kek)
	if !ok {
		return nil, secret.ErrWrongPassphrase
	}
	copy(ek[:], ekBuf)

	return file.NewStore(v.baseDir, ".harp", crypter{ek}), nil
}

type crypter struct{ key [keySize]byte }

func (c crypter) Encrypt(entryName, content string) (ciphertext []byte, _ error) {
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("could not generate nonce: %w", err)
	}

	encryptedContent := secretbox.Seal(nil, []byte(content), &nonce, &c.key)
	ciphertext, err := proto.Marshal(&epb.Entry{
		EncryptedContent: encryptedContent,
		Nonce:            nonce[:],
	})
	if err != nil {
		return nil, fmt.Errorf("could not marshal entry: %w", err)
	}
	return ciphertext, nil
}

func (c crypter) Decrypt(entryName string, ciphertext []byte) (content string, _ error) {
	entry := &epb.Entry{}
	if err := proto.Unmarshal(ciphertext, entry); err != nil {
		return "", fmt.Errorf("could not unmarshal entry: %w", err)
	}
	var nonce [nonceSize]byte
	copy(nonce[:], entry.Nonce)

	contentBytes, ok := secretbox.Open(nil, entry.EncryptedContent, &nonce, &c.key)
	if !ok {
		return "", errors.New("could not decrypt")
	}
	return string(contentBytes), nil
}
