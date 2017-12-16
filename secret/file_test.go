package file

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestGetPutDelete(t *testing.T) {
	t.Parallel()

	// Initialization.
	dir, err := getDir()
	if err != nil {
		t.Fatalf("Could not get temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)
	store := NewStore(dir, ".foo", fakeCrypter{})

	// Basic tests.
	if err := store.Put("entry", "content"); err != nil {
		t.Fatalf("Could not put: %v", err)
	}
	content, err := store.Get("entry")
	if err != nil {
		t.Fatalf("Could not get: %v", err)
	}
	if content != "content" {
		t.Fatalf("Content was unexpected: %q", content)
	}
	if err := store.Delete("entry"); err != nil {
		t.Fatalf("Could not delete: %v", err)
	}
	if content, err := store.Get("entry"); err == nil {
		t.Fatalf("Could unexpectedly get content: %q", content)
	}

	// Directory navigation tests.
	if err := store.Put("/path/to/entry", "content"); err != nil {
		t.Fatalf("Could not put: %v", err)
	}
	content, err = store.Get("/path/to/entry")
	if err != nil {
		t.Fatalf("Could not get: %v", err)
	}
	if content != "content" {
		t.Fatalf("Content was unexpected: %q", content)
	}
	if err := store.Delete("/path/to/entry"); err != nil {
		t.Fatalf("Could not delete: %v", err)
	}
	if content, err := store.Get("/path/to/entry"); err == nil {
		t.Fatalf("Could unexpectedly get content: %q", content)
	}
}

func TestDirectoryTraversal(t *testing.T) {
	t.Parallel()

	// Initialization.
	dir, err := getDir()
	if err != nil {
		t.Fatalf("Could not get temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)
	innerDir := filepath.Join(dir, "inner")
	outerStore := NewStore(dir, ".foo", fakeCrypter{})
	if err != nil {
		t.Fatalf("Could not create outer password store: %v", err)
	}
	innerStore := NewStore(innerDir, ".foo", fakeCrypter{})
	if err != nil {
		t.Fatalf("Could not create inner password store: %v", err)
	}

	// Both can put into their own, outer can put into inner, but inner can't put into outer.
	if err := outerStore.Put("/vault", "outer content"); err != nil {
		t.Fatalf("Could not put content in outer store: %v", err)
	}
	if err := innerStore.Put("/vault", "inner content"); err != nil {
		t.Fatalf("Could not put content in inner store: %v", err)
	}
	if err := outerStore.Put("/inner/vault2", "outer content in inner space"); err != nil {
		t.Fatalf("Could not put content from outer to inner: %v", err)
	}
	if err := innerStore.Put("../vault", "inner content in outer space"); err == nil {
		t.Fatalf("Could put content from inner to outer")
	}

	// Inner can read inner but not outer; outer can read both.
	if _, err := outerStore.Get("/vault"); err != nil {
		t.Fatalf("Could not get content in outer store: %v", err)
	}
	if _, err := innerStore.Get("/vault"); err != nil {
		t.Fatalf("Could not get content in inner store: %v", err)
	}
	if _, err := outerStore.Get("/inner/vault2"); err != nil {
		t.Fatalf("Could not get content from inner with outer: %v", err)
	}
	if _, err := innerStore.Get("../vault"); err == nil {
		t.Fatalf("Could get content from outer with inner")
	}

	// Inner can delete inner but not outer; outer can delete both.
	if err := innerStore.Delete("../vault"); err == nil {
		t.Fatalf("Could delete content from outer with inner")
	}
	if err := outerStore.Delete("/vault"); err != nil {
		t.Fatalf("Could not delete content in outer store: %v", err)
	}
	if err := innerStore.Delete("/vault"); err != nil {
		t.Fatalf("Could not delete content in inner store: %v", err)
	}
	if err := outerStore.Delete("/inner/vault2"); err != nil {
		t.Fatalf("Could not delete content in inner from outer: %v", err)
	}
}

func getDir() (string, error) {
	dir, err := ioutil.TempDir("", ".gopass_tmp_")
	if err != nil {
		return "", err
	}
	if err := os.Remove(dir); err != nil {
		return "", err
	}
	return dir, nil
}

type fakeCrypter struct{}

func (fakeCrypter) Encrypt(entryName, content string) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "ENCRYPTED:%s", content)
	return buf.Bytes(), nil
}

func (fakeCrypter) Decrypt(entryName string, ciphertext []byte) (string, error) {
	if !bytes.HasPrefix(ciphertext, []byte("ENCRYPTED:")) {
		return "", errors.New("not encrypted")
	}
	return string(bytes.TrimPrefix(ciphertext, []byte("ENCRYPTED:"))), nil
}
