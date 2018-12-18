package eqi

import (
	"github.com/polyverse/ropoly/lib/types"
	"net/url"
)

func HighestOffsetCountEqi(f1, f2 types.Fingerprint, form url.Values) (float64, error) {
	offsetCounts := map[types.Offset]int{}
	count := 0
	for gadget, oldAddresses := range f1 {
		count += len(oldAddresses)
		newAddresses := f2[gadget]
		for _, oldAddress := range oldAddresses {
			/*DEBUG*/ zeroOffset := false
			for _, newAddress := range newAddresses {
				offset := types.Offset(newAddress - oldAddress)
				/*DEBUG*/ if offset == 0 {
					if zeroOffset {
						/*DEBUG*/ println(gadget, oldAddress, newAddress)
					} else {
						zeroOffset = true
					}
				}
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
	return float64(maxOffsetCount) / float64(count), nil
}