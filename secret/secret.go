// Package secret provides a standard interface to access serialized secret
// data for harpocrates.
package secret

import (
	"errors"
)

var (
	ErrWrongPassphrase = errors.New("wrong passphrase")
	ErrNoEntry         = errors.New("no such password store entry")
)

// Vault represents a passphrase-locked "vault" of secret
// data. Before data can be accessed, it must be unlocked. Vault instances are
// safe for concurrent access from multiple goroutines.
type Vault interface {
	// Unlock attempts to open the vault. On success, a Store instance is
	// returned. If an incorrect passphrase is provided, ErrWrongPassphrase
	// is returned.
	Unlock(passphrase string) (Store, error)
}

// Store represents a serialized store of key-value entries. The keys can be
// thought of as a service name (e.g. "My Bank"), while the values are some
// content about the corresponding service which should be kept secret (e.g.
// username, password, security questions, etc).
//
// Entries are named with absolute slash-separated paths, for example
// `/path/to/entry-name`. There is no restriction on what can be stored as
// content. Store implementations will always store entry content securely, but
// may choose not to store entry names securely.
//
// Store instances are safe for concurrent access from multiple goroutines.
// However, they make no attempt to provide any form of transactionality, so an
// update implemented as a Get() followed by a Put() may overwrite intervening
// changes by another goroutine or process.
type Store interface {
	// List returns all of the entries in the password store. Entry names
	// will conform to the format described in the Store interface's godoc.
	List() (entries []string, _ error)

	// Get gets an entry's contents given its name. The entry name should
	// conform to the format described in the Store interface's godoc. If
	// there is no entry with the given name, ErrNoEntry is returned.
	Get(entry string) (content string, _ error)

	// Put updates an entry's contents to the given value. The entry name
	// should conform to the format described in the Store interface's
	// godoc.
	Put(entry, content string) error

	// Delete removes an entry by name. The entry name should conform to
	// the format returned by List(). If there is no entry with the given
	// name, ErrNoEntry is returned.
	Delete(entry string) error
}
