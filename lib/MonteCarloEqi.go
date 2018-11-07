package lib

import (
	"errors"
	"math/rand"
	"net/url"
	"strconv"
	"github.com/polyverse/ropoly/lib/types"
)

func monteCarloEqi(comparison types.FingerprintComparison, form url.Values) (float64, error) {
	min, err := strconv.ParseInt(form.Get("min"), 0, 64)
	if err != nil {
		return 0, errors.New("Could not parse min.")
	}
	max, err := strconv.ParseInt(form.Get("max"), 0, 64)
	if err != nil {
		return 0, errors.New("Could not parse max.")
	}
	trials, err := strconv.ParseInt(form.Get("trials"), 0, 64)
	if err != nil {
		return 0, errors.New("Could not parse number of trials.")
	}

	displacementSets := make([]map[types.Offset]bool, 0)
	for _, displacements := range comparison.GadgetDisplacements {
		displacementSets = append(displacementSets, offsetSet(displacements))
	}

	sum := 0
	if len(displacementSets) > 0 {
		for i := int64(0); i < trials; i++ {
			if monteCarloTrial(displacementSets, min, max) {
				sum++
			}
		}
	}
	return float64(sum) / float64(trials), nil
}

func monteCarloTrial(displacements []map[types.Offset]bool, minGadgets, maxGadgets int64) bool {
	numGadgets := minGadgets
	if maxGadgets > minGadgets {
		numGadgets += rand.Int63n(maxGadgets - minGadgets)
	}

	workingOffsetSet := offsetSetCopy(randomGadgetDisplacementSet(displacements))
	for i := int64(1); i < numGadgets && len(workingOffsetSet) > 0; i++ {
		gadgetOffsetSet := randomGadgetDisplacementSet(displacements)
		offsetSetAndEqual(&workingOffsetSet, &gadgetOffsetSet)
	}
	return len(workingOffsetSet) > 0
}

func randomGadgetDisplacementSet(displacements []map[types.Offset]bool) map[types.Offset]bool {
	index := rand.Intn(len(displacements))
	return displacements[index]
}

func offsetSet(values []types.Offset) map[types.Offset]bool {
	ret := map[types.Offset]bool{}
	for i := 0; i < len(values); i++ {
		ret[values[i]] = true
	}
	return ret
}

func offsetSetAndEqual(dest, other *map[types.Offset]bool) {
	for value, _ := range *dest {
		if !(*other)[value] {
			delete(*dest, value)
		}
	}
}

func offsetSetCopy(s map[types.Offset]bool) map[types.Offset]bool {
	ret := map[types.Offset]bool{}
	for key, value := range s {
		ret[key] = value
	}
	return ret
}