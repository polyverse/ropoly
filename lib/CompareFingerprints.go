package lib

import (
	"github.com/polyverse/ropoly/lib/types"
)

func CompareFingerprints(f1 types.Fingerprint, f2 types.Fingerprint) types.FingerprintComparison {
	return f1.CompareTo(f2)
}
