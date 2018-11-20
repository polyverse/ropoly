package eqi

import (
	"github.com/polyverse/ropoly/lib/types"
	"math"
	"net/url"
	"strconv"
)

const defaultOrder = 2.0

func CountPolynomialEqi(comparison types.FingerprintComparison, form url.Values) (float64, error) {
	order, err := strconv.ParseFloat(form.Get("order"), 64)
	if err != nil {
		order = defaultOrder
	}

	if form.Get("single") == "true" {
		return countPolynomialEqiSingleOffset(comparison, order), nil
	} else {
		return countPolynomialEqiMultiOffset(comparison, order), nil
	}
}

func countPolynomialEqiMultiOffset(comparison types.FingerprintComparison, order float64) float64 {
	powerSum := 0.0
	for _, count := range comparison.GadgetsByOffset {
		powerSum += math.Pow(float64(count), order)
	}
	return powerSum / math.Pow(float64(len(comparison.GadgetDisplacements)), order)
}

func countPolynomialEqiSingleOffset(comparison types.FingerprintComparison, order float64) float64 {
	powerSum := math.Pow(float64(comparison.SurvivedGadgetCount), order)
	for _, count := range comparison.GadgetsBySingleOffset {
		powerSum += math.Pow(float64(count), order)
	}
	return powerSum / math.Pow(float64(len(comparison.GadgetDisplacements)), order)
}
