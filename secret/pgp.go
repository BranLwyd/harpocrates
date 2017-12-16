// Package pgp provides a simple interface to interact with password stores
// compatible with the `pass` standard password manager. For more information
// about `pass`, see https://www.passwordstore.org. (The author of this package
// is not in any way associated with the authors of pass.)
package pgp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/file"
	"github.com/BranLwyd/harpocrates/secret/key_private"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/ripemd160"

	pb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

func init() {
	key_private.RegisterVaultFromKeyFunc(func(location string, key *pb.Key) (secret.Vault, error) {
		if k := key.GetPgpKey(); k != nil {
			return newVault(location, string(k.GetSerializedEntity()))
		}
		return nil, nil
	})
}

// NewVault creates a new vault using data in an existing directory `baseDir`
// encrypted with the private key serialized in `serializedEntity`.
// TODO(bran): make this private (only called by the RegisterVaultFromKeyFunc function)
func newVault(baseDir, serializedEntity string) (secret.Vault, error) {
	return &vault{
		baseDir:          filepath.Clean(baseDir),
		serializedEntity: serializedEntity,
	}, nil
}

// vault implements secret.Vault.
type vault struct {
	baseDir          string // base directory containing password entries
	serializedEntity string // entity used to encrypt/decrypt password entries
}

func (v *vault) Unlock(passphrase string) (secret.Store, error) {
	// Read entity, decrypt keys using passphrase.
	entity, err := openpgp.ReadEntity(packet.NewReader(strings.NewReader(v.serializedEntity)))
	if err != nil {
		return nil, fmt.Errorf("could not read entity: %v", err)
	}
	pb := []byte(passphrase)
	if err := entity.PrivateKey.Decrypt(pb); err != nil {
		return nil, secret.ErrWrongPassphrase
	}
	for _, sk := range entity.Subkeys {
		if err := sk.PrivateKey.Decrypt(pb); err != nil {
			return nil, secret.ErrWrongPassphrase
		}
	}

	return file.NewStore(v.baseDir, ".gpg", crypter{entity}), nil
}

// crypter implements file.Crypter.
type crypter struct {
	entity *openpgp.Entity
}

func (c crypter) Encrypt(entry, content string) (ciphertext []byte, _ error) {
	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{c.entity}, c.entity, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("could not start encrypting password content: %v", err)
	}
	if _, err := io.Copy(w, strings.NewReader(content)); err != nil {
		return nil, fmt.Errorf("could not write encrypted content: %v", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("could not finish writing encrypted content: %v", err)
	}
	return buf.Bytes(), nil
}

func (c crypter) Decrypt(entry string, ciphertext []byte) (content string, _ error) {
	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext), openpgp.EntityList{c.entity}, nil, nil)
	if err != nil {
		return "", fmt.Errorf("could not read PGP message: %v", err)
	}
	contentBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("could not read PGP message body: %v", err)
	}
	if md.SignatureError != nil {
		return "", fmt.Errorf("message verification error: %v", md.SignatureError)
	}
	return string(contentBytes), nil
}
