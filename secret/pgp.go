// Package pgp provides a simple interface to interact with password stores
// compatible with the `pass` standard password manager. For more information
// about `pass`, see https://www.passwordstore.org. (The author of this package
// is not in any way associated with the authors of pass.)
package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
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
			return NewVault(location, string(k.GetSerializedEntity()))
		}
		return nil, nil
	})
}

// InitVault initializes a new vault in the given base directory with the given
// entity. The directory is created if needed. This function will fail if
// called on a directory that has already been initialized.
// TODO(bran): remove?
func InitVault(baseDir string, entity *openpgp.Entity) (retErr error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return fmt.Errorf("could not create directory %q: %v", baseDir, err)
	}
	file, err := os.OpenFile(filepath.Join(baseDir, ".gpg-id"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("could not open file %q for writing: %v", filepath.Join(baseDir, ".gpg-id"), err)
	}
	defer func() {
		file.Close()
		if retErr != nil {
			os.Remove(file.Name())
		}
	}()
	var ident string
	for id := range entity.Identities {
		// TODO(bran): allow identity to be chosen?
		ident = id
		break
	}
	if ident == "" {
		return errors.New("entity has no identity")
	}
	if _, err := fmt.Fprintf(file, "%s\n", ident); err != nil {
		return fmt.Errorf("could not write to %q: %v", filepath.Join(baseDir, ".gpg-id"), err)
	}
	return nil
}

// NewVault creates a new vault using data in an existing directory `baseDir`
// encrypted with the private key serialized in `serializedEntity`.
// TODO(bran): make this private (only called by the RegisterVaultFromKeyFunc function)
func NewVault(baseDir, serializedEntity string) (secret.Vault, error) {
	baseDir = filepath.Clean(baseDir)

	// Check that this entity is appropriate for the selected directory &
	// that its keys are already decrypted.
	entity, err := openpgp.ReadEntity(packet.NewReader(strings.NewReader(serializedEntity)))
	if err != nil {
		return nil, fmt.Errorf("could not read entity: %v", err)
	}
	keyID, err := keyID(baseDir)
	if err != nil {
		return nil, fmt.Errorf("could not get key ID: %v", err)
	}
	if _, ok := entity.Identities[keyID]; !ok {
		return nil, errors.New("wrong entity")
	}

	return &vault{
		baseDir:          baseDir,
		serializedEntity: serializedEntity,
	}, nil
}

// keyID gets the identity of the key used to create the given password store
// directory.
// TODO(bran): put this in the key instead of reading it off of the disk
func keyID(baseDir string) (string, error) {
	content, err := ioutil.ReadFile(filepath.Join(baseDir, ".gpg-id"))
	if err != nil {
		return "", fmt.Errorf("could not read %q: %v", filepath.Join(baseDir, ".gpg-id"), err)
	}
	idx := bytes.IndexByte(content, '\n')
	if idx == -1 {
		return string(content), nil
	}
	return string(content[:idx]), nil
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
