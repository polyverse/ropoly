package lib

import (
	"math/rand"
)

const monteCarloMinGadgets = 3
const monteCarloMaxGadgets = 25
const monteCarloNumTrials = 1000000

func monteCarloEqi(comparison FingerprintRegionComparison) float64 {
	displacementSets := make([]map[int64]bool, 0)
	for _, displacements := range comparison.GadgetDisplacements {
		displacementSets = append(displacementSets, int64Set(displacements))
	}

	sum := 0
	for i := 0; i < monteCarloNumTrials; i++ {
		if monteCarloTrial(displacementSets) {
			sum++
		}
	}
	return float64(sum) / monteCarloNumTrials
}

func monteCarloTrial(displacements []map[int64]bool) bool {
	numGadgets := monteCarloMinGadgets + rand.Intn(monteCarloMaxGadgets - monteCarloMinGadgets)

	workingOffsetSet := int64SetCopy(randomGadgetDisplacementSet(displacements))
	for i := 1; i < numGadgets && len(workingOffsetSet) > 0; i++ {
		gadgetOffsetSet := randomGadgetDisplacementSet(displacements)
		int64SetAndEqual(&workingOffsetSet, &gadgetOffsetSet)
	}
	return len(workingOffsetSet) > 0
}

func randomGadgetDisplacementSet(displacements []map[int64]bool) map[int64]bool {
	index := rand.Intn(len(displacements))
	return displacements[index]
}

func int64Set(values []int64) map[int64]bool {
	ret := map[int64]bool{}
	for i := 0; i < len(values); i++ {
		ret[values[i]] = true
	}
	return ret
}

func int64SetAndEqual(dest, other *map[int64]bool) {
	for value, _ := range *dest {
		if !(*other)[value] {
			delete(*dest, value)
		}
	}
}

func int64SetCopy(s map[int64]bool) map[int64]bool {
	ret := map[int64]bool{}
	for key, value := range s {
		ret[key] = value
	}
	return ret
}