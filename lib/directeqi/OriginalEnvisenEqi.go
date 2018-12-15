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
	total := 0

	for gadget, oldAddresses := range f1 {
		total += len(oldAddresses)
		newAddresses := f2[gadget]
		if newAddresses == nil {
			/*DEBUG*/ println("Died:", gadget)
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
				/*DEBUG*/ println("Survived at", oldAddress.String(), gadget)
				survived++
			} else {
				/*DEBUG*/ println("Moved from", oldAddress.String(), "to", (oldAddress + types.Addr(offset)).String())
				moved++
				offsetCounts[offset]++
			}
		}
	}
	
	/*DEBUG*/ println("dead:", dead)
	/*DEBUG*/ println("moved:", moved)
	/*DEBUG*/ println("survived:", survived)
	/*DEBUG*/ println("total:", total)
	deadPercent := float64(dead * 100) / float64(total)
	/*DEBUG*/ println("deadPercent:", deadPercent)
	/*DEBUG*/ println("survivedPercent:", float64(survived * 100) / float64(total))
	/*DEBUG*/ println("movedPercent:", float64(moved * 100) / float64(total))
	movementQuality := movementQuality(moved, offsetCounts)
	/*DEBUG*/ println("movementQuality:", movementQuality)
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