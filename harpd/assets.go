package assets

import "fmt"

func MustAsset(name string) []byte {
	a, ok := Asset[name]
	if !ok {
		panic(fmt.Sprintf("Asset %q does not exist", name))
	}
	return a
}
