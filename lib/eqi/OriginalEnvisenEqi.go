package eqi

import (
	"github.com/polyverse/ropoly/lib/types"
	"math"
	"net/url"
)

func OriginalEnvisenEqi(c types.FingerprintComparison, _ url.Values) (float64, error) {
	return strongSurvival(c) + (weakSurvivalOnly(c) * movementQuality(c)), nil
}

func strongSurvival(c types.FingerprintComparison) float64 {
	return float64(c.SurvivedGadgetCount) / float64(len(c.GadgetDisplacements))
}

func weakSurvivalOnly(c types.FingerprintComparison) float64 {
	return weakSurvival(c) - strongSurvival(c)
}

func weakSurvival(c types.FingerprintComparison) float64 {
	return float64(len(c.SingleDisplacements)) / float64(len(c.GadgetDisplacements))
}

func movementQuality(c types.FingerprintComparison) float64 {
	if len(c.GadgetsBySingleOffset) <= 1 {
		return 0.0
	}
	return numberOfOffsets(c) * offsetStandardDeviation(c) / numberOfMovedGadgets(c) / highestOffsetCount(c)
}

func numberOfOffsets(c types.FingerprintComparison) float64 {
	return float64(len(c.GadgetsBySingleOffset))
}

func offsetStandardDeviation(c types.FingerprintComparison) float64 {
	mean := meanOffset(c)
	totalSquareDeviation := 0.0
	for _, count := range c.GadgetsBySingleOffset {
		deviation := float64(count) - mean
		totalSquareDeviation += deviation * deviation
	}
	return math.Sqrt(totalSquareDeviation / (float64(len(c.GadgetsBySingleOffset)) - 1))
}

func meanOffset(c types.FingerprintComparison) float64 {
	return offsetTotal(c) / float64(len(c.GadgetsBySingleOffset))
}

func offsetTotal(c types.FingerprintComparison) float64 {
	total := 0
	for _, count := range c.GadgetsBySingleOffset {
		total += count
	}
	return float64(total)
}

func numberOfMovedGadgets(c types.FingerprintComparison) float64 {
	return float64(len(c.SingleDisplacements))
}

func highestOffsetCount(c types.FingerprintComparison) float64 {
	highest := 0
	for _, count := range c.GadgetsBySingleOffset {
		if count > highest {
			highest = count
		}
	}
	return float64(highest)
}
