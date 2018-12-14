package directeqi

import (
	"github.com/polyverse/ropoly/lib/types"
	"math"
)

func OriginalEnvisenEqi(f1, f2 types.Fingerprint) types.EntropyQualityIndex {
	dead := 0
	survived := 0
	gadgetOffsets := map[types.Addr]types.Offset{}
	offsetCounts := map[types.Offset]int{}

	for gadget, oldAddresses := range f1 {
		newAddresses := f2[gadget]
		if newAddresses == nil {
			dead += len(oldAddresses)
			continue
		}
		for i := 0; i < len(oldAddresses); i++ {
			oldAddress := oldAddresses[i]
			offset := types.Offset(newAddresses[0] - oldAddress)
			for i := 0; i < len(newAddresses); i++ {
				newAddress := newAddresses[i]
				if newAddress < oldAddress {
					offset = types.Offset(newAddress - oldAddress)
				} else if offset >= 0 {
					break
				} else {
					offsetCandidate := types.Offset(newAddress - oldAddress)
					if offsetCandidate < -offset {
						offset = offsetCandidate
						break
					}
				}
			}
			if offset == 0 {
				survived++
			} else {
				gadgetOffsets[oldAddress] = offset
				offsetCounts[offset]++
			}
		}
	}

	total := dead + survived + len(gadgetOffsets)
	deadPercent := float64(dead * 100) / float64(total)
	movementQuality := movementQuality(gadgetOffsets, offsetCounts)
	return types.EntropyQualityIndex(deadPercent + movementQuality)
}

func movementQuality(gadgetOffsets map[types.Addr]types.Offset, offsetCounts map[types.Offset]int) float64 {
	if len(gadgetOffsets) == 0 {
		return 0.0
	}
	return (1.0 - (float64(offsetStdev(offsetCounts)) / float64(valueMax(offsetCounts)))) * float64(len(offsetCounts) * 100) / float64(len(gadgetOffsets))
}

func valueMax(m map[types.Offset]int) int {
	max := 0
	for _, value := range m {
		if value > max {
			max = value
		}
	}
	return max
}

func offsetStdev(m map[types.Offset]int) float64 {
	total := 0
	for _, count := range m {
		total += count
	}
	mean := float64(total) / float64(len(m))

	totalDeviation := 0.0
	for _, count := range m {
		difference := float64(count) - mean
		deviation := difference * difference
		totalDeviation += deviation
	}
	return math.Sqrt(totalDeviation / float64(len(m)))
}