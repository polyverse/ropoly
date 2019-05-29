package lib

import (
	"github.com/polyverse/ropoly/lib/types"
)

func HighestOffsetCount(f1, f2 types.Fingerprint) (int, types.Offset) {
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

	var maxOffset types.Offset
	maxOffsetCount := 0
	for offset, offsetCount := range offsetCounts {
		if offsetCount > maxOffsetCount {
			maxOffset = offset
			maxOffsetCount = offsetCount
		}
	}
	return maxOffsetCount, maxOffset
}