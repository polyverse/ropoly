package lib

/*
func originalEnvisenEqi(comparison FingerprintRegionComparison, _ url.Values) (float64, error) {
	survived, _, offsets := survivedDeadOffsets(comparison)
	fractionSurvivedGadgets := float64(survived) / float64(len(comparison.GadgetDisplacements))
	if len(offsets) == 0 {
		return fractionSurvivedGadgets, nil
	}

	offsetCounts := gadgetsByOffset(offsets)
	movementScale := float64(len(offsetCounts)) / float64(len(offsets))

	highestOffsetCount := 0
	totalOffsetCount := 0
	for _, count := range offsetCounts {
		totalOffsetCount += count
		if count > highestOffsetCount {
			highestOffsetCount = count
		}
	}
	meanOffsetCount := float64(totalOffsetCount) / float64(len(offsetCounts))
	totalSquareDeviation := float64(0)
	for _, count := range offsetCounts {
		deviation := float64(count) - meanOffsetCount
		squareDeviation := deviation * deviation
		totalSquareDeviation += squareDeviation
	}
	offsetStdev := math.Sqrt(totalSquareDeviation / float64(len(offsetCounts)))
	movementPathologicalness := offsetStdev / float64(highestOffsetCount)

	return fractionSurvivedGadgets + (movementScale * movementPathologicalness), nil
}

func survivedDeadOffsets(comparison FingerprintRegionComparison) (int, int, map[disasm.Ptr]int64) {
	survived := 0
	dead := 0
	offsets := map[disasm.Ptr]int64{}

	for origin, displacements := range comparison.GadgetDisplacements {
		if len(displacements) == 0 {
			dead++
		} else if includes(displacements, 0) {
			survived++
		} else {
			smallestOffset := displacements[0]
			for i := 1; i < len(displacements); i++ {
				offset := displacements[i]
				if abs(offset) < abs(smallestOffset) {
					smallestOffset = offset
				}
			}
			offsets[origin] = smallestOffset
		}
	}
	return survived, dead, offsets
}

func includes(s []int64, n int64) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == n {
			return true
		}
	}
	return false
}

func abs(i int64) int64 {
	if i >= 0 {
		return i
	} else {
		return -i
	}
}

func gadgetsByOffset(offsets map[disasm.Ptr]int64) map[int64]int {
	ret := map[int64]int{}
	for _, offset := range offsets {
		ret[offset]++
	}
	return ret
}
*/