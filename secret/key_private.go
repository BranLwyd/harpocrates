// Package key_private provides package-private functionality to support the
// key package.
package key_private

import (
	"errors"

	"github.com/BranLwyd/harpocrates/secret"

	pb "github.com/BranLwyd/harpocrates/proto/key_go_proto"
)

var (
	vaultFromKeyFuncs []VaultFromKeyFunc
)

// VaultFromKeyFunc is a function that may be able to generate a vault from a
// key. It should return the vault if it can. It should return (nil, nil) if
// it does not recognize the key. It should return an error if it recognizes
// the key but the key is invalid in some way.
type VaultFromKeyFunc func(location string, _ *pb.Key) (secret.Vault, error)

// RegisterVaultFromKeyFunc registers a VaultFromKeyFunc for handling keys. It
// should be called only from init().
func RegisterVaultFromKeyFunc(f VaultFromKeyFunc) {
	vaultFromKeyFuncs = append(vaultFromKeyFuncs, f)
}

// VaultFromKey attempts to create a Vault from a given key.
func VaultFromKey(location string, key *pb.Key) (secret.Vault, error) {
	for _, f := range vaultFromKeyFuncs {
		v, err := f(location, key)
		if err != nil {
			return nil, err
		}
		if v != nil {
			return v, nil
		}
	}
	return nil, errors.New("unrecognized key type")
}
