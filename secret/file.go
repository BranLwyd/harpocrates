// Package file provides common functionality for secret.Store implementations
// based on a directory structure holding regular files, each file holding
// encrypted entry content.
package file

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/BranLwyd/harpocrates/secret"
)

func NewStore(baseDir, extension string, crypter Crypter) secret.Store {
	if extension != "" && !strings.HasPrefix(extension, ".") {
		extension = "." + extension
	}
	return &store{
		baseDir:   filepath.Clean(baseDir),
		extension: extension,
		crypter:   crypter,
	}
}

// Crypter is an interface used to determine how a file.store encrypts files on disk.
type Crypter interface {
	// Encrypt encrypts the given plaintext `entryContent` into
	// `ciphertext`, which will then be written to a file on disk.
	// `entryName` is the name of the entry this content is for.
	Encrypt(entryName, entryContent string) (ciphertext []byte, _ error)

	// Decrypt attempts to decrypt the given `ciphertext` (read from disk)
	// into plaintext `entryContent`. `entryName` is the name of the entry
	// this ciphertext is for.
	Decrypt(entryName string, ciphertext []byte) (entryContent string, _ error)
}

// store implements secret.Store.
type store struct {
	baseDir   string
	extension string
	crypter   Crypter
}

// List helps to implement secret.Store.
func (s *store) List() ([]string, error) {
	var entries []string
	if err := filepath.Walk(s.baseDir, func(path string, info os.FileInfo, inErr error) error {
		switch {
		case inErr != nil:
			return fmt.Errorf("couldn't walk %q: %w", path, inErr)

		case !info.IsDir() && strings.HasSuffix(path, s.extension):
			entry, err := filepath.Rel(s.baseDir, strings.TrimSuffix(path, s.extension))
			if err != nil {
				return fmt.Errorf("couldn't get relative path of %q: %w", path, err)
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
		return "", fmt.Errorf("couldn't get entry filename for %q: %w", entry, err)
	}
	ciphertext, err := ioutil.ReadFile(entryFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return "", secret.ErrNoEntry
		}
		return "", fmt.Errorf("couldn't read %q: %w", entryFilename, err)
	}
	content, err := s.crypter.Decrypt(entry, ciphertext)
	if err != nil {
		return "", fmt.Errorf("couldn't decrypt: %w", err)
	}
	return content, nil
}

// Put helps to implement secret.Store.
//
// On POSIX-compliant systems, the update is atomic.
func (s *store) Put(entry, content string) error {
	ciphertext, err := s.crypter.Encrypt(entry, content)
	if err != nil {
		return fmt.Errorf("couldn't encrypt: %w", err)
	}

	entryFilename, err := s.getEntryFilename(entry)
	if err != nil {
		return fmt.Errorf("couldn't get entry filename for %q: %w", entry, err)
	}
	entryDir := filepath.Dir(entryFilename)
	if err := os.MkdirAll(entryDir, 0770); err != nil {
		return fmt.Errorf("couldn't create directory %q: %w", entryDir, err)
	}
	tempFile, err := ioutil.TempFile(entryDir, ".gopass_tmp_")
	if err != nil {
		return fmt.Errorf("couldn't create temporary file: %w", err)
	}
	tempFilename := tempFile.Name()
	defer os.Remove(tempFilename)
	defer tempFile.Close()
	if err := os.Chmod(tempFilename, 0660); err != nil {
		return fmt.Errorf("couldn't set permissions: %w", err)
	}
	if _, err := tempFile.Write(ciphertext); err != nil {
		return fmt.Errorf("couldn't write encrypted content: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("couldn't close %q: %w", tempFile.Name(), err)
	}
	if err := os.Rename(tempFilename, entryFilename); err != nil {
		return fmt.Errorf("couldn't rename %q -> %q: %w", tempFilename, entryFilename, err)
	}
	return nil
}

// Delete helps to implement secret.Store.
func (s *store) Delete(entry string) error {
	entryFilename, err := s.getEntryFilename(entry)
	if err != nil {
		return fmt.Errorf("couldn't get entry filename for %q: %w", entry, err)
	}
	if err := os.Remove(entryFilename); err != nil {
		if os.IsNotExist(err) {
			return secret.ErrNoEntry
		}
		return fmt.Errorf("couldn't delete %q: %w", entryFilename, err)
	}

	// Clean up newly-empty directories.
	for entryDir := filepath.Dir(entryFilename); strings.HasPrefix(entryDir, s.baseDir); entryDir = filepath.Dir(entryDir) {
		remove, err := func() (bool, error) {
			dirFile, err := os.Open(entryDir)
			if err != nil {
				return false, fmt.Errorf("couldn't open directory %q: %w", err)
			}
			defer dirFile.Close()
			if _, err := dirFile.Readdir(1); err == io.EOF {
				return true, nil
			}
			return false, err
		}()
		if err != nil {
			return fmt.Errorf("couldn't readdir %q: %w", entryDir, err)
		}
		if !remove {
			break
		}
		if err := os.Remove(entryDir); err != nil {
			return fmt.Errorf("couldn't delete %q: %w", entryDir, err)
		}
	}
	return nil
}

func (s *store) getEntryFilename(entry string) (string, error) {
	if entry == "" {
		return "", errors.New("missing entry")
	}
	entryFilename := filepath.Join(s.baseDir, entry+s.extension)

	// Check that we haven't walked out of the base dir.
	if !strings.HasPrefix(entryFilename, s.baseDir) {
		return "", errors.New("invalid entry")
	}

	return entryFilename, nil
}
