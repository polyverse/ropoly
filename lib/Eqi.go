package lib

import (
	"errors"
	"math"
)

func Eqi(comparison FingerprintComparison, eqiFunc string) (EqiResult, error) {
	ret := EqiResult{
		Eqi: float64(0),
	}

	for i := 0; i < len(comparison.SharedRegionComparisons); i++ {
		regionComparison := comparison.SharedRegionComparisons[i]
		f := regionEqiFuncs[eqiFunc]
		if f == nil {
			return EqiResult{}, errors.New("EQI function not recognized")
		}
		eqi := regionEqiFuncs[eqiFunc](regionComparison)
		ret.RegionEqis = append(ret.RegionEqis, RegionEqi {
			Region: regionComparison.Region,
			Eqi: normalizeEqi(eqi),
		})
		ret.Eqi += math.Pow(eqi, 2.0)
	}

	ret.Eqi = normalizeEqi(math.Sqrt(ret.Eqi))
	return ret, nil
}

type regionEqiFunc func(FingerprintRegionComparison) float64

var regionEqiFuncs = map[string]regionEqiFunc {
	"monte-carlo": monteCarloEqi,
}

func normalizeEqi(eqi float64) float64 {
	return 100.0 * (1.0 - eqi)
}