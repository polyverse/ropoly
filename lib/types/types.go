package types

import (
	"github.com/polyverse/disasm"
)

type FingerprintComparison struct {
	GadgetDisplacements map[disasm.Ptr][]int64    `json:"gadgetDisplacements"`
	NewGadgets          map[GadgetId][]disasm.Ptr `json:"newGadgets"`
	GadgetsByOffset     map[int64]int             `json:"gadgetCountsByOffset"`
}

type GadgetId string

type Fingerprint map[GadgetId][]disasm.Ptr

func FingerprintFromGadgets(gadgets []*disasm.Gadget) Fingerprint {
	fingerprint := Fingerprint{}
	for _, gadget := range gadgets {
		hash := GadgetId(gadget.InstructionString())
		if _, ok := fingerprint[hash]; !ok {
			fingerprint[hash] = []disasm.Ptr{gadget.Address}
		} else {
			fingerprint[hash] = append(fingerprint[hash], gadget.Address)
		}
	}

	return fingerprint
}

func (f1 Fingerprint) CompareTo(f2 Fingerprint) FingerprintComparison {
	ret := FingerprintComparison{
		GadgetDisplacements: map[disasm.Ptr][]int64{},
		NewGadgets:          map[GadgetId][]disasm.Ptr{},
		GadgetsByOffset:     map[int64]int{},
	}

	for gadget, oldAddresses := range f1 {
		newAddresses := f1[gadget]
		for _, oldAddress := range oldAddresses {
			offsets := make([]int64, len(newAddresses))
			for j, newAddress := range newAddresses {
				offset := int64(newAddress) - int64(oldAddress)
				offsets[j] = offset
				ret.GadgetsByOffset[offset]++
			}
			ret.GadgetDisplacements[oldAddress] = offsets
		}
	}

	for gadget, addresses := range f2 {
		if f1[gadget] == nil {
			ret.NewGadgets[gadget] = addresses
		}
	}

	return ret
}
