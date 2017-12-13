// Package key provides functions to allow handling keys.
package key

import (
	"github.com/BranLwyd/harpocrates/secret"
	"github.com/BranLwyd/harpocrates/secret/key_private"
	_ "github.com/BranLwyd/harpocrates/secret/pgp"

	pb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

// NewVault creates a new vault from the given key, reading encrypted data from
// the given location (which has a key-type specific meaning).
func NewVault(location string, key *pb.Key) (secret.Vault, error) {
	return key_private.VaultFromKey(location, key)
}
