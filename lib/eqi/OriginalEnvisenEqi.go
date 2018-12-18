package directeqi

import (
	"github.com/polyverse/ropoly/lib/types"
	"math"
)

func OriginalEnvisenEqi(f1, f2 types.Fingerprint) types.EntropyQualityIndex {
	dead := 0
	survived := 0
	moved := 0
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
			}
		}
	}

	for gadget, newAddresses := range f2 {
		oldAddresses := f1[gadget]
		if oldAddresses == nil {
			continue
		}
		for i := 0; i < len(newAddresses); i++ {
			newAddress := newAddresses[i]
			offset := types.Offset(newAddress - oldAddresses[len(oldAddresses) - 1])
			for i := len(oldAddresses) - 2; i >= 0; i-- {
				offsetCandidate := types.Offset(newAddress - oldAddresses[i])
				if (offsetCandidate < 0) || (-offset > offsetCandidate) {
					offset = offsetCandidate
				} else {
					break
				}
			}
			if offset != 0 {
				moved++
				offsetCounts[offset]++
			}
		}
	}

	total := dead + moved + survived
	deadPercent := float64(dead * 100) / float64(total)
	movementQuality := movementQuality(moved, offsetCounts)
	return types.EntropyQualityIndex(deadPercent + movementQuality)
}

func movementQuality(moved int, offsetCounts map[types.Offset]int) float64 {
	if moved == 0 {
		return 0.0
	}
	return (1.0 - (float64(offsetStdev(offsetCounts)) / float64(valueMax(offsetCounts)))) * float64(len(offsetCounts) * 100) / float64(moved)
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