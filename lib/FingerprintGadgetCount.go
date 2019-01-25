package lib

import (
	"github.com/polyverse/ropoly/lib/types"
)

func GadgetCount(f1 types.Fingerprint) int {
	count := 0
	for _, addresses := range f1 {
		count += len(addresses)
	}
	return count
}