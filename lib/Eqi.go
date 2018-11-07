package lib

import (
	"errors"
	"net/url"
	"github.com/polyverse/ropoly/lib/types"
)

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

type regionEqiFunc func(types.FingerprintComparison, url.Values) (float64, error)

var regionEqiFuncs = map[string]regionEqiFunc{
	"monte-carlo":      monteCarloEqi,
	"envisen-original": originalEnvisenEqi,
}

func normalizeEqi(eqi float64) types.EntropyQualityIndex {
	return types.EntropyQualityIndex(100.0 * (1.0 - eqi))
}