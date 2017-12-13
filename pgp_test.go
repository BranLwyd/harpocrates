package pgp

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func TestInitVault(t *testing.T) {
	t.Parallel()

	// Initialization.
	dir, err := getDir()
	if err != nil {
		t.Fatalf("Could not get temporary directory: %v", err)
	}
	t.Logf("Got temporary directory %q", dir)
	defer os.RemoveAll(dir)

	firstEntity, err := openpgp.NewEntity("first entity", "some comment", "email@example.com", nil)
	if err != nil {
		t.Fatalf("Could not create entity: %v", err)
	}
	secondEntity, err := openpgp.NewEntity("second entity", "", "", nil)
	if err != nil {
		t.Fatalf("Could not create entity: %v", err)
	}

	// A call to InitVault should create a directory with a .gpg-id file in it.
	if err := InitVault(dir, firstEntity); err != nil {
		t.Fatalf("InitStore failed: %v", err)
	}
	gpgIdContent, err := ioutil.ReadFile(filepath.Join(dir, ".gpg-id"))
	if err != nil {
		t.Fatalf("Could not read .gpg-id: %v", err)
	}
	if string(gpgIdContent) != "first entity (some comment) <email@example.com>\n" {
		t.Fatalf("Content of .gpg-id unexpected: %q", string(gpgIdContent))
	}

	// A second call to InitStore should fail, and not modify the existing .gpg-id file.
	if err := InitVault(dir, secondEntity); err == nil {
		t.Fatalf("Second InitStore unexpectedly succeeded")
	}
	gpgIdContent, err = ioutil.ReadFile(filepath.Join(dir, ".gpg-id"))
	if err != nil {
		t.Fatalf("Could not read .gpg-id: %v", err)
	}
	if string(gpgIdContent) != "first entity (some comment) <email@example.com>\n" {
		t.Fatalf("Content of .gpg-id unexpectedly changed after second call to InitStore: %q", string(gpgIdContent))
	}
}

func TestGetPutDelete(t *testing.T) {
	t.Parallel()

	// Initialization.
	dir, err := getDir()
	if err != nil {
		t.Fatalf("Could not get temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)
	entity, err := openpgp.NewEntity("entity", "", "", nil)
	if err != nil {
		t.Fatalf("Could not create entity: %v", err)
	}
	if err := InitVault(dir, entity); err != nil {
		t.Fatalf("Could not initialize password store: %v", err)
	}
	store := newStore(dir, entity)

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
	entity, err := openpgp.NewEntity("entity", "", "", nil)
	if err != nil {
		t.Fatalf("Could not create entity: %v", err)
	}
	if err := InitVault(dir, entity); err != nil {
		t.Fatalf("Could not initialize outer password store: %v", err)
	}
	outerStore := newStore(dir, entity)
	if err != nil {
		t.Fatalf("Could not create outer password store: %v", err)
	}
	if err := InitVault(innerDir, entity); err != nil {
		t.Fatalf("Could not initialize inner password store: %v", err)
	}
	innerStore := newStore(innerDir, entity)
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

func newStore(baseDir string, entity *openpgp.Entity) *store {
	return &store{
		baseDir: baseDir,
		entity:  entity,
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
