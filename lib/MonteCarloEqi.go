package lib

import (
	"errors"
	"math/rand"
	"net/url"
	"strconv"
)

func monteCarloEqi(comparison FingerprintRegionComparison, form url.Values) (float64, error) {
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

	displacementSets := make([]map[int64]bool, 0)
	for _, displacements := range comparison.GadgetDisplacements {
		displacementSets = append(displacementSets, int64Set(displacements))
	}

	sum := 0
	for i := int64(0); i < trials; i++ {
		if monteCarloTrial(displacementSets, min, max) {
			sum++
		}
	}
	return float64(sum) / float64(trials), nil
}

func monteCarloTrial(displacements []map[int64]bool, minGadgets, maxGadgets int64) bool {
	numGadgets := minGadgets
	if maxGadgets > minGadgets {
		numGadgets += rand.Int63n(maxGadgets - minGadgets)
	}

	workingOffsetSet := int64SetCopy(randomGadgetDisplacementSet(displacements))
	for i := int64(1); i < numGadgets && len(workingOffsetSet) > 0; i++ {
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
