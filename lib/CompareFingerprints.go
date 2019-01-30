package lib

import (
	"github.com/polyverse/ropoly/lib/types"
)

func CompareFingerprints(f1, f2 types.Fingerprint, includeSurvived bool) types.FingerprintComparison {
	return f1.CompareTo(f2, includeSurvived)
}
