package eqi

import (
	"github.com/polyverse/ropoly/lib/types"
	"math"
	"net/url"
)

func OriginalEnvisenEqi(comparison types.FingerprintComparison, _ url.Values) (float64, error) {
	gadgetCount := len(comparison.GadgetDisplacements)
	weaklySurvivedCount := len(comparison.SingleDisplacements)
	fractionSurvivedGadgets := float64(comparison.SurvivedGadgetCount) / float64(gadgetCount)
	if weaklySurvivedCount == 0 {
		return fractionSurvivedGadgets, nil
	}

	movementScale := float64(weaklySurvivedCount) / float64(gadgetCount)

	highestOffsetCount := 0
	meanOffsetCount := float64(weaklySurvivedCount) / float64(len(comparison.GadgetsBySingleOffset))
	totalSquareDeviation := float64(0)
	for _, count := range comparison.GadgetsBySingleOffset {
		if count > highestOffsetCount {
			highestOffsetCount = count
		}
		deviation := float64(count) - meanOffsetCount
		squareDeviation := deviation * deviation
		totalSquareDeviation += squareDeviation
	}
	offsetStdev := math.Sqrt(totalSquareDeviation / float64(len(comparison.GadgetsBySingleOffset)))
	movementPathologicalness := offsetStdev / float64(highestOffsetCount)

	return fractionSurvivedGadgets + (movementScale * movementPathologicalness), nil
}
