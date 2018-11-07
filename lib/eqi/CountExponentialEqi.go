package eqi

import (
	"math"
	"net/url"
	"strconv"
	"github.com/polyverse/ropoly/lib/types"
)

const defaultBase = 2.0

func CountExponentialEqi(comparison types.FingerprintComparison, form url.Values) (float64, error) {
	base, err := strconv.ParseFloat(form.Get("base"), 64)
	if err != nil {
		base = defaultBase
	}

	if form.Get("single") == "true" {
		return countExponentialEqiSingleOffset(comparison, base), nil
	} else {
		return countExponentialEqiMultiOffset(comparison, base), nil
	}
}

func countExponentialEqiMultiOffset(comparison types.FingerprintComparison, base float64) float64 {
	powerSum := 0.0
	for _, count := range comparison.GadgetsByOffset {
		powerSum += math.Pow(base, float64(count))
	}
	return powerSum / math.Pow(base, float64(len(comparison.GadgetDisplacements)))
}

func countExponentialEqiSingleOffset(comparison types.FingerprintComparison, base float64) float64 {
	powerSum := math.Pow(base, float64(comparison.SurvivedGadgetCount))
	for _, count := range comparison.GadgetsBySingleOffset {
		powerSum += math.Pow(base, float64(count))
	}
	return powerSum / math.Pow(base, float64(len(comparison.GadgetDisplacements)))
}