package lib

import (
	"errors"
	"github.com/polyverse/ropoly/lib/eqi"
	"github.com/polyverse/ropoly/lib/types"
	"math"
	"net/url"
)

func DirectEqi(f1 types.Fingerprint, f2 types.Fingerprint, eqiFunc string, form url.Values) (types.EntropyQualityIndex, error) {
	if eqiFunc == "envisen-original" {
		return eqi.OriginalEnvisenEqi(f1, f2), nil
	}

	normalized := form.Get("normalized") == "true"

	function := directEqiFuncs[eqiFunc]
	if function == nil {
		return types.EntropyQualityIndex(0), errors.New("EQI function not recognized.")
	}

	eqi, err := function(f1, f2, form)
	if err != nil {
		return types.EntropyQualityIndex(0), err
	}
	return normalizeEqi(eqi, eqiFunc, normalized), nil
}

type directEqiFunc func(types.Fingerprint, types.Fingerprint, url.Values) (float64, error)

var directEqiFuncs = map[string]directEqiFunc {
	"monte-carlo":          eqi.MonteCarloEqi,
	"shared-offsets":       eqi.SharedOffsetsPerGadgetEqi,
	"offsets-intersection": eqi.OffsetsIntersectionEqi,
	"highest-offset-count": eqi.HighestOffsetCountEqi,
}

func normalizeEqi(eqi float64, eqiFunc string, normalized bool) types.EntropyQualityIndex {
	ret := 100.0 * (1.0 - eqi)
	if normalized {
		ret = 1.7626080809865 * (math.Pow(1.04139221012755, ret) - 1)
	}
	return types.EntropyQualityIndex(ret)
}
