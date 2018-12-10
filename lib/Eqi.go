package lib

import (
	"errors"
	"github.com/polyverse/ropoly/lib/directeqi"
	"github.com/polyverse/ropoly/lib/eqi"
	"github.com/polyverse/ropoly/lib/types"
	"net/url"
)

func DirectEqi(f1 types.Fingerprint, f2 types.Fingerprint, eqiFunc string, form url.Values) (types.EntropyQualityIndex, error) {
	function := directEqiFuncs[eqiFunc]
	if function == nil {
		return types.EntropyQualityIndex(0), errors.New("EQI function not recognized.")
	}

	eqi, err := function(f1, f2, form)
	if err != nil {
		return types.EntropyQualityIndex(0), err
	}
	return normalizeEqi(eqi), nil
}

func Eqi(comparison types.FingerprintComparison, eqiFunc string, form url.Values) (types.EntropyQualityIndex, error) {
	f := regionEqiFuncs[eqiFunc]
	if f == nil {
		return types.EntropyQualityIndex(0), errors.New("EQI function not recognized")
	}

	eqi, err := regionEqiFuncs[eqiFunc](comparison, form)
	if err != nil {
		return types.EntropyQualityIndex(0), err
	}
	return normalizeEqi(eqi), nil
}

type directEqiFunc func(types.Fingerprint, types.Fingerprint, url.Values) (float64, error)

var directEqiFuncs = map[string]directEqiFunc {
	"monte-carlo":      directeqi.MonteCarloEqi,
	"shared-offsets":   directeqi.SharedOffsetsPerGadgetEqi,
}

type regionEqiFunc func(types.FingerprintComparison, url.Values) (float64, error)

var regionEqiFuncs = map[string]regionEqiFunc {
	"monte-carlo":      eqi.MonteCarloEqi,
	"envisen-original": eqi.OriginalEnvisenEqi,
	"count-poly":       eqi.CountPolynomialEqi,
	"count-exp":        eqi.CountExponentialEqi,
	"shared-offsets":   eqi.SharedOffsetsPerGadgetEqi,
}

func normalizeEqi(eqi float64) types.EntropyQualityIndex {
	return types.EntropyQualityIndex(100.0 * (1.0 - eqi))
}
