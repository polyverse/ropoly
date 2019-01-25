package lib

import (
	"github.com/polyverse/ropoly/lib/types"
)

func GadgetSurvival(f1, f2 types.Fingerprint) int {
	survived := 0
	for gadget, oldAddresses := range f1 {
		newAddresses := f2[gadget]
		iOld := 0
		iNew := 0
		for iOld < len(oldAddresses) && iNew < len(newAddresses) {
			if oldAddresses[iOld] == newAddresses[iNew] {
				survived++
				iOld++
				iNew++
			} else if oldAddresses[iOld] < newAddresses[iNew] {
				iOld++
			} else {
				iNew++
			}
		}
	}
	return survived
}