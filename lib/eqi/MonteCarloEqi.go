package eqi

import (
	"errors"
	"github.com/polyverse/ropoly/lib/types"
	"math/rand"
	"net/url"
	"strconv"
)

type gadgetIndexer struct {
	sequence types.GadgetId
	addressIndex int
}

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

	gis := gadgetIndexers(f1)

	sum := 0
	for i := 0; i < int(trials); i++ {
		if monteCarloTrial(f1, f2, gis, min, max) {
			sum++
		}
	}
	return float64(sum) / float64(trials), nil
}

func monteCarloTrial(f1, f2 types.Fingerprint, gadgetIndexers []gadgetIndexer, minGadgets, maxGadgets int64) bool {
	numGadgets := minGadgets
	if maxGadgets > minGadgets {
		numGadgets += rand.Int63n(maxGadgets - minGadgets)
	}

	workingOffsetSet := offsetSetCopy(randomGadgetDisplacementSet(f1, f2, gadgetIndexers))
	for i := int64(1); i < numGadgets && len(workingOffsetSet) > 0; i++ {
		gadgetOffsetSet := randomGadgetDisplacementSet(f1, f2, gadgetIndexers)
		offsetSetAndEqual(&workingOffsetSet, &gadgetOffsetSet)
	}
	return len(workingOffsetSet) > 0
}

func randomGadgetDisplacementSet(f1, f2 types.Fingerprint, gadgetIndexers []gadgetIndexer) map[types.Offset]bool {
	index := rand.Intn(len(gadgetIndexers))
	return offsetSetByIndex(f1, f2, gadgetIndexers[index])
}

func gadgetIndexers(f types.Fingerprint) []gadgetIndexer {
	var indexers []gadgetIndexer
	for sequence, addresses := range f {
		for i := range addresses {
			indexers = append(indexers, gadgetIndexer {
				sequence:   sequence,
				addressIndex:  i,
			})
		}
	}
	return indexers
}

func offsetSetByIndex(f1, f2 types.Fingerprint, gi gadgetIndexer) map[types.Offset]bool {
	oldAddress := f1[gi.sequence][gi.addressIndex]
	newAddresses := f2[gi.sequence]
	offsets := make([]types.Offset, len(newAddresses), len(newAddresses))
	for i := 0; i < len(newAddresses); i++ {
		offsets[i] = types.Offset(newAddresses[i] - oldAddress)
	}
	return offsetSet(offsets)
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