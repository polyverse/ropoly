package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
)

func Fingerprint(spec GadgetSearchSpec) (FingerprintResult, error, []error) {
	fingerprint := map[memaccess.MemoryRegion]map[Sig][]disasm.Ptr{}
	var section memaccess.MemoryRegion
	harderror, softerrors := OperateOnGadgets(spec, func(region memaccess.MemoryRegion) {
		section = region
	}, func(gadget Gadget) {
		if (fingerprint[section]) == nil {
			fingerprint[section] = map[Sig][]disasm.Ptr{}
		}
		fingerprint[section][gadget.Signature] = append(fingerprint[section][gadget.Signature], gadget.Address)
	})

	return FingerprintResult{fingerprint}, harderror, softerrors
}