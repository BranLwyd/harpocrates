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

	// Only store the required entity in the keyring.
	return &store{
		baseDir: v.baseDir,
		entity:  entity,
	}, nil
}

// store implements secret.Store.
//
// The entries are serialized to disk. The key of each entry is used to
// determine a filename, which should contain slash-separated paths and a final
// entry name. (Note that this implies that the service name itself is not kept
// secret to anyone who can access the password store files.) The entry content
// is encrypted using GPG.
type store struct {
	baseDir string
	entity  *openpgp.Entity
}

// List helps to implement secret.Store.
func (s *store) List() ([]string, error) {
	var entries []string
	if err := filepath.Walk(s.baseDir, func(path string, info os.FileInfo, inErr error) error {
		switch {
		case inErr != nil:
			return fmt.Errorf("could not walk %q: %v", path, inErr)

		case !info.IsDir() && strings.HasSuffix(path, ".gpg"):
			entry, err := filepath.Rel(s.baseDir, strings.TrimSuffix(path, ".gpg"))
			if err != nil {
				return fmt.Errorf("could not get relative path of %q: %v", path, err)
			}
			entries = append(entries, "/"+entry)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

// Get helps to implement secret.Store.
func (s *store) Get(entry string) (string, error) {
	entryFilename, err := s.getEntryFilename(entry)
	if err != nil {
		return "", fmt.Errorf("could not get entry filename for %q: %v", entry, err)
	}
	entryFile, err := os.Open(entryFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return "", secret.ErrNoEntry
		}
		return "", fmt.Errorf("could not open %q for reading: %v", entryFilename, err)
	}
	defer entryFile.Close()
	md, err := openpgp.ReadMessage(entryFile, openpgp.EntityList{s.entity}, nil, nil)
	if err != nil {
		return "", fmt.Errorf("could not read PGP message: %v", err)
	}
	entryContent, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("could not read PGP message body: %v", err)
	}
	if md.SignatureError != nil {
		return "", fmt.Errorf("message verification error: %v", md.SignatureError)
	}
	return string(entryContent), nil
}

// Put helps to implement secret.Store.
//
// On POSIX-compliant systems, the update is atomic.
func (s *store) Put(entry string, content string) error {
	entryFilename, err := s.getEntryFilename(entry)
	if err != nil {
		return fmt.Errorf("could not get entry filename for %q: %v", entry, err)
	}
	entryDir := filepath.Dir(entryFilename)
	if err := os.MkdirAll(entryDir, 0700); err != nil {
		return fmt.Errorf("could not create directory %q: %v", entryDir, err)
	}
	tempFile, err := ioutil.TempFile(entryDir, ".gopass_tmp_")
	if err != nil {
		return fmt.Errorf("could not create temporary file: %v", err)
	}
	tempFilename := tempFile.Name()
	defer os.Remove(tempFilename)
	defer tempFile.Close()
	w, err := openpgp.Encrypt(tempFile, []*openpgp.Entity{s.entity}, s.entity, nil, nil)
	if err != nil {
		return fmt.Errorf("could not start encrypting password content: %v", err)
	}
	defer w.Close()
	if _, err := io.Copy(w, strings.NewReader(content)); err != nil {
		return fmt.Errorf("could not write encrypted content: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("could not finish writing encrypted content: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("could not close %q: %v", tempFile.Name(), err)
	}
	if err := os.Rename(tempFilename, entryFilename); err != nil {
		return fmt.Errorf("could not rename %q -> %q: %v", tempFilename, entryFilename, err)
	}
	return nil
}

// Delete helps to implement secret.Store.
func (s *store) Delete(entry string) error {
	entryFilename, err := s.getEntryFilename(entry)
	if err != nil {
		return fmt.Errorf("could not get entry filename for %q: %v", entry, err)
	}
	if err := os.Remove(entryFilename); err != nil {
		if os.IsNotExist(err) {
			return secret.ErrNoEntry
		}
		return fmt.Errorf("could not delete %q: %v", entryFilename, err)
	}

	// Clean up newly-empty directories.
	for entryDir := filepath.Dir(entryFilename); strings.HasPrefix(entryDir, s.baseDir); entryDir = filepath.Dir(entryDir) {
		remove, err := func() (bool, error) {
			dirFile, err := os.Open(entryDir)
			if err != nil {
				return false, fmt.Errorf("could not open directory %q: %v", err)
			}
			defer dirFile.Close()
			if _, err := dirFile.Readdir(1); err == io.EOF {
				return true, nil
			} else {
				return false, err
			}
		}()
		if err != nil {
			return fmt.Errorf("could not readdir %q: %v", entryDir, err)
		}
		if !remove {
			break
		}
		if err := os.Remove(entryDir); err != nil {
			return fmt.Errorf("could not delete %q: %v", entryDir, err)
		}
	}
	return nil
}

func (s *store) getEntryFilename(entry string) (string, error) {
	if entry == "" {
		return "", errors.New("missing entry")
	}
	entryFilename := filepath.Join(s.baseDir, entry+".gpg")

	// Check that we haven't walked out of the base dir.
	if !strings.HasPrefix(entryFilename, s.baseDir) {
		return "", errors.New("invalid entry")
	}

	return entryFilename, nil
}
