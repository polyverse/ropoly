package lib

import (
	"errors"
	"github.com/polyverse/ropoly/lib/types"
	"math"
	"net/url"
)

func Eqi(comparison types.FingerprintComparison, eqiFunc string, form url.Values) (types.Eqi, error) {
	ret := types.Eqi{
		Aggregate: types.EntropyQualityIndex(0),
	}

	for i := 0; i < len(comparison.SharedRegionComparisons); i++ {
		regionComparison := comparison.SharedRegionComparisons[i]
		f := regionEqiFuncs[eqiFunc]
		if f == nil {
			return types.Eqi{}, errors.New("EQI function not recognized")
		}
		eqi, err := regionEqiFuncs[eqiFunc](regionComparison, form)
		if err != nil {
			return types.Eqi{}, err
		}
		ret.Regional = append(ret.Regional, types.RegionalEqi{
			Region: regionComparison.Region,
			Eqi:    normalizeEqi(eqi),
		})
		ret.Aggregate += types.EntropyQualityIndex(math.Pow(eqi, 2.0))
	}

	ret.Aggregate = normalizeEqi(math.Sqrt(float64(ret.Aggregate)))
	return ret, nil
}

type regionEqiFunc func(types.FingerprintRegionComparison, url.Values) (float64, error)

var regionEqiFuncs = map[string]regionEqiFunc{
	"monte-carlo":      monteCarloEqi,
	"envisen-original": originalEnvisenEqi,
}

func normalizeEqi(eqi float64) types.EntropyQualityIndex {
	return types.EntropyQualityIndex(100.0 * (1.0 - eqi))
}
