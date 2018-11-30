package eqi

import (
	"github.com/polyverse/ropoly/lib/types"
	"net/url"
)

func SharedOffsetsPerGadgetEqi(c types.FingerprintComparison, form url.Values) (float64, error) {
	totalEqi := 0.0
	perGadgetEqiMethod := getPerGadgetEqiMethod(form)
	gadgetCount := len(c.GadgetDisplacements)
	for _, displacements := range c.GadgetDisplacements {
		gadgetEqi := perGadgetEqiMethod(displacements, c.GadgetsByOffset, gadgetCount)
		totalEqi += gadgetEqi
	}
	averageEqi := totalEqi / float64(gadgetCount)
	return averageEqi, nil
}

type perGadgetEqiFunction func([]types.Offset, map[types.Offset]int, int) float64

var perGadgetEqiMethods = map[string]perGadgetEqiFunction{
	"worst-only":            perGadgetWorstOffset,
	"multiplicative":        perGadgetInverseProductInverse,
	"additive":              perGadgetAdditive,
	"additive-with-ceiling": perGadgetAdditiveWithCeiling,
	"closest-only":          perGadgetClosest,
}

func getPerGadgetEqiMethod(form url.Values) perGadgetEqiFunction {
	method := perGadgetEqiMethods[form.Get("multiple-handling")]
	if method == nil {
		return perGadgetWorstOffset
	}
	return method
}

func perGadgetWorstOffset(displacements []types.Offset, gadgetsByDisplacement map[types.Offset]int, totalGadgets int) float64 {
	maxOffsetCount := 0
	for i := 0; i < len(displacements); i++ {
		displacement := displacements[i]
		offsetCount := gadgetsByDisplacement[displacement]
		if maxOffsetCount < offsetCount {
			maxOffsetCount = offsetCount
		}
	}
	return float64(maxOffsetCount) / float64(totalGadgets)
}

func perGadgetInverseProductInverse(displacements []types.Offset, gadgetsByDisplacement map[types.Offset]int, totalGadgets int) float64 {
	quality := 1.0
	for i := 0; i < len(displacements); i++ {
		displacement := displacements[i]
		offsetCount := gadgetsByDisplacement[displacement]
		quality *= 1.0 - (float64(offsetCount) / float64(totalGadgets))
	}
	return 1.0 - quality
}

func perGadgetAdditive(displacements []types.Offset, gadgetsByDisplacement map[types.Offset]int, totalGadgets int) float64 {
	totalOffsetCount := 0
	for i := 0; i < len(displacements); i++ {
		displacement := displacements[i]
		offsetCount := gadgetsByDisplacement[displacement]
		totalOffsetCount += offsetCount
	}
	return float64(totalOffsetCount) / float64(totalGadgets)
}

func perGadgetAdditiveWithCeiling(displacements []types.Offset, gadgetsByDisplacement map[types.Offset]int, totalGadgets int) float64 {
	eqi := perGadgetAdditive(displacements, gadgetsByDisplacement, totalGadgets)
	if eqi > 1.0 {
		eqi = 1.0
	}
	return eqi
}

func perGadgetClosest(displacements []types.Offset, gadgetsByDisplacement map[types.Offset]int, totalGadgets int) float64 {
	if len(displacements) == 0 {
		return 0.0
	}

	displacement := displacements[0]
	for i := 1; i < len(displacements); i++ {
		if abs(displacements[i]) < abs(displacement) {
			displacement = displacements[0]
			break
		}
	}

	return float64(gadgetsByDisplacement[displacement]) / float64(totalGadgets)
}

func abs(o types.Offset) types.Offset {
	if o < types.Offset(0) {
		return -o
	} else {
		return o
	}
}
