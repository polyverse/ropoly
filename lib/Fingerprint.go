package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
)

func Fingerprint(spec GadgetSearchSpec) (FingerprintResult, error, []error) {
	fingerprint := map[string]*FingerprintRegion{}
	var section memaccess.MemoryRegion
	harderror, softerrors := OperateOnGadgets(spec, func(region memaccess.MemoryRegion) {
		section = region
	}, func(gadget Gadget) {
		if (fingerprint[section.Kind]) == nil {
			fingerprint[section.Kind] = new(FingerprintRegion)
			fingerprint[section.Kind].Region = section
			fingerprint[section.Kind].Gadgets = map[Sig][]disasm.Ptr{}
		}
		fingerprint[section.Kind].Gadgets[gadget.Signature] = append(fingerprint[section.Kind].Gadgets[gadget.Signature], gadget.Address)
	})

	return FingerprintResult{fingerprint}, harderror, softerrors
}

func CompareFingerprints(old, new FingerprintResult) FingerprintComparison {
	return compareFingerprints(old.Regions, new.Regions)
}

func compareFingerprints(old, new map[string]*FingerprintRegion) FingerprintComparison {
	ret := FingerprintComparison{}

	for regionName, mapping := range old {
		if new[regionName] == nil {
			ret.RemovedRegions = append(ret.RemovedRegions, mapping.Region)
		} else {
			ret.SharedRegionComparisons = append(ret.SharedRegionComparisons, compareFingerprintRegions(*old[regionName], *new[regionName]))
		}
	}
	for regionName, mapping := range new {
		if old[regionName] == nil {
			ret.AddedRegions = append(ret.AddedRegions, mapping.Region)
		}
	}

	return ret
}

func compareFingerprintRegions(old FingerprintRegion, new FingerprintRegion) FingerprintRegionComparison {
	ret := FingerprintRegionComparison {
		Region: old.Region,
		Displacement: int64(new.Region.Address) - int64(old.Region.Address),
		GadgetDisplacements: map[disasm.Ptr][]int64{},
		AddedGadgets: map[Sig][]disasm.Ptr{},
		NumOldGadgets: 0,
		GadgetsByOffset: map[int64]int{},
	}

	for sig, addresses := range old.Gadgets {
		newAddresses := new.Gadgets[sig]
		for i := 0; i < len(addresses); i++ {
			oldAddress := addresses[i]
			offsets := make([]int64, len(newAddresses))
			for j := 0; j < len(offsets); j++ {
				offset := int64(newAddresses[j]) - int64(oldAddress)
				offsets[j] = offset
				ret.GadgetsByOffset[offset]++
			}
			ret.GadgetDisplacements[oldAddress] = offsets
		}
		ret.NumOldGadgets += len(addresses)
	}

	for sig, addresses := range new.Gadgets {
		if old.Gadgets[sig] == nil {
			ret.AddedGadgets[sig] = addresses
		}
	}

	chiSquaredSum := 0
	for _, count := range ret.GadgetsByOffset {
		chiSquared := count * count
		chiSquaredSum += chiSquared
	}
	ret.Eqi = (1.0 - (float64(chiSquaredSum) / float64(ret.NumOldGadgets * ret.NumOldGadgets))) * 100.0

	return ret
}