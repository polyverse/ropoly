package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
)

func OperateOnGadgets(spec GadgetSearchSpec, regionOperation func(memaccess.MemoryRegion), gadgetOperation func(Gadget)) (error, []error) {
	var opError error

	regionsError, softerrors := OperateOnRegions(spec, func(region memaccess.MemoryRegion, info disasm.Info, start uint64, end uint64) bool {
		regionOperation(region)

		numRegionGadgets, error := operateOnRegionGadgets(spec, region, info, start, end, gadgetOperation)
		if error != nil {
			opError = error
			return false
		}

		spec.LimitN -= numRegionGadgets
		return spec.LimitN > 0
	})
	if opError != nil {
		return opError, softerrors
	}
	return regionsError, softerrors
}

func operateOnRegionGadgets(spec GadgetSearchSpec, region memaccess.MemoryRegion, info disasm.Info, start uint64, end uint64, operation func(Gadget)) (uint64, error) {
	disAsmSpec := spec
	disAsmSpec.LimitN = spec.EndN - spec.StartN
	disAsmRegion, error := disassembleRegion(disAsmSpec, region, info, start, end, true)
	instructions := disAsmRegion.Instructions
	if error != nil {
		return 0, error
	}

	foundEarly := map[int]*[]disasm.Instruction{}
	numGadgets := uint64(0)

	var index int
	for index = 0; index < len(instructions) && numGadgets < spec.LimitN; index++ {
		if foundEarly[index] == nil {
			found, gadgetInstructions := gadgetAtIndex(index, instructions, spec)
			if found {
				operation(gadget(gadgetInstructions))
				numGadgets += 1
				for i := 1; i < len(gadgetInstructions) && numGadgets+uint64(len(foundEarly)) < spec.LimitN; i++ {
					subgadgetInstructions := gadgetInstructions[i:]
					foundEarly[i] = &subgadgetInstructions
				}
			}
		} else {
			operation(gadget(*foundEarly[index]))
			numGadgets += 1
			delete(foundEarly, index)
		}
	}

	return numGadgets, nil
}
