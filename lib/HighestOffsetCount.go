package lib

import (
	"github.com/polyverse/ropoly/lib/types"
)

func HighestOffsetCount(f1, f2 types.Fingerprint) int {
	offsetCounts := map[types.Offset]int{}
	count := 0
	for gadget, oldAddresses := range f1 {
		count += len(oldAddresses)
		newAddresses := f2[gadget]
		for _, oldAddress := range oldAddresses {
			for _, newAddress := range newAddresses {
				offset := types.Offset(newAddress - oldAddress)
				offsetCounts[offset] += 1
			}
		}
	}

	maxOffsetCount := 0
	for _, offsetCount := range offsetCounts {
		if offsetCount > maxOffsetCount {
			maxOffsetCount = offsetCount
		}
	}
	return maxOffsetCount
}