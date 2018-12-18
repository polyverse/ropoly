package eqi

import (
	"errors"
	"github.com/polyverse/ropoly/lib/types"
	"math/rand"
	"net/url"
	"strconv"
)

func MonteCarloEqi(f1 types.Fingerprint, f2 types.Fingerprint, form url.Values) (float64, error) {
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

	offsets := offsetSets(f1, f2)

	sum := 0
	for i := 0; i < int(trials); i++ {
		if monteCarloTrial(offsets, min, max) {
			sum++
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

func offsetSets(f1, f2 types.Fingerprint) []map[types.Offset]bool {
	ret := make([]map[types.Offset]bool, 0)
	for gadget, addresses := range f1 {
		for i := 0; i < len(addresses); i++ {
			oldAddress := addresses[i]
			newAddresses := f2[gadget]
			offsets := make([]types.Offset, len(newAddresses), len(newAddresses))
			for i := 0; i < len(newAddresses); i++ {
				offsets[i] = types.Offset(newAddresses[i] - oldAddress)
			}
			ret = append(ret, offsetSet(offsets))
		}
	}
	return ret
}

func randomGadgetDisplacementSet(displacements []map[types.Offset]bool) map[types.Offset]bool {
	index := rand.Intn(len(displacements))
	return displacements[index]
}