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

	"golang.org/x/crypto/openpgp"
	_ "golang.org/x/crypto/ripemd160"
)

var (
	ErrNoEntry = errors.New("no such password store entry")
)

// Store represents a store of key-value entries. The keys can be thought of as
// a service name (e.g. "My Bank"), while the values are some content about the
// corresponding service which should be kept secret (e.g.  username, password,
// security questions, etc).
//
// The entries are serialized to disk. The key of each entry is used to
// determine a filename, which should contain slash-separated paths and a final
// entry name. (Note that this implies that the service name itself is not kept
// secret to anyone who can access the password store files.) The entry content
// is encrypted using GPG.
//
// Store instances are safe for concurrent access from multiple goroutines.
// However, they make no attempt to provide any form of transactionality, so an
// update implemented as a Get() followed by a Put() may overwrite intervening
// changes by another goroutine or process.
type Store struct {
	baseDir string
	entity  *openpgp.Entity
}

// InitStore initializes a new store in the given base directory with the given
// entity. The directory is created if needed. This function will fail if
// called on a directory that has already been initialized.
func InitStore(baseDir string, entity *openpgp.Entity) (retErr error) {
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
		// TODO: allow identity to be chosen?
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

// NewStore creates a new Store with the given base directory, which must
// already exist & be initialized, and using the given GPG entity, which must
// already have its keys decrypted.
func NewStore(baseDir string, entity *openpgp.Entity) (*Store, error) {
	// Check that this entity is appropriate for the selected directory &
	// that its keys are already decrypted.
	keyID, err := KeyID(baseDir)
	if err != nil {
		return nil, fmt.Errorf("could not get key ID: %v", err)
	}
	if _, ok := entity.Identities[keyID]; !ok {
		return nil, errors.New("wrong entity")
	}
	if entity.PrivateKey.Encrypted {
		return nil, errors.New("key is encrypted")
	}
	for _, sk := range entity.Subkeys {
		if sk.PrivateKey.Encrypted {
			return nil, errors.New("key is encrypted")
		}
	}

	// Only store the required entity in the keyring.
	return &Store{
		baseDir: filepath.Clean(baseDir),
		entity:  entity,
	}, nil
}

// KeyID gets the identity of the key used to create the given password store
// directory.
func KeyID(baseDir string) (string, error) {
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

// List returns all of the entries currently existing in the password store in
// lexical order. Entries contained in a subdirectory take the form
// /path/to/entry-name.
func (s *Store) List() ([]string, error) {
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

// Get gets an entry's contents given its name. The entry name should conform
// to the format returned by List().
func (s *Store) Get(entry string) (string, error) {
	entryFilename, err := s.getEntryFilename(entry)
	if err != nil {
		return "", fmt.Errorf("could not get entry filename for %q: %v", entry, err)
	}
	entryFile, err := os.Open(entryFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoEntry
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

// Put updates an entry's contents to the given value. The entry name should
// conform to the format returned by List().
//
// On POSIX-compliant systems, the update is atomic.
func (s *Store) Put(entry string, content string) error {
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

// Delete removes an entry by name. The entry name should conform to the format
// returned by List().
func (s *Store) Delete(entry string) error {
	entryFilename, err := s.getEntryFilename(entry)
	if err != nil {
		return fmt.Errorf("could not get entry filename for %q: %v", entry, err)
	}
	if err := os.Remove(entryFilename); err != nil {
		if os.IsNotExist(err) {
			return ErrNoEntry
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

func (s *Store) getEntryFilename(entry string) (string, error) {
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
