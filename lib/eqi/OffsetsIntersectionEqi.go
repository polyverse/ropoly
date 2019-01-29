package eqi

import (
	"errors"
	"github.com/polyverse/ropoly/lib/types"
	"math"
	"net/url"
	"strconv"
)

func OffsetsIntersectionEqi(f1, f2 types.Fingerprint, form url.Values) (float64, error) {
	length, err := strconv.ParseUint(form.Get("length"), 0, 64)
	if err != nil {
		return 0, errors.New("Could not parse length.")
	}
	if length == 0 {
		return 1.0, nil
	}

	offsets := offsetSets(f1, f2)

	totalAttacks := math.Pow(float64(len(offsets)), float64(length))
	successfulAttacks := float64(successfulAttacks([]int{}, offsets, int(length)))
	return successfulAttacks / totalAttacks, nil
}

func successfulAttacks(chosenIndices []int, offsets []map[types.Offset]bool, length int) int {
	if len(chosenIndices) == int(length) {
		workingOffsetSet := offsetSetCopy(offsets[chosenIndices[0]])
		for i := 1; i < len(chosenIndices); i++ {
			index := chosenIndices[i]
			set := offsets[index]
			for offset, _ := range workingOffsetSet {
				if !set[offset] {
					delete(workingOffsetSet, offset)
				}
			}
		}
		if len(workingOffsetSet) == 0 {
			return 0
		} else {
			return 1
		}
	}

	sum := 0
	for i := 0; i < len(offsets); i++ {
		sum += successfulAttacks(append(chosenIndices, i), offsets, length)
	}
	return sum
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