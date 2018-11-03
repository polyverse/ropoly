package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
)

func DisAsm(spec GadgetSearchSpec, disassembleAll bool) (DisAsmResult, error, []error) {
	var harderror error
	var softerrors []error
	var regions []DisAsmRegion

	regionsHarderror, regionsSofterrors := OperateOnRegions(spec, func(region memaccess.MemoryRegion, info disasm.Info, pc uint64, end uint64) bool {
		var regionInstructions []disasm.Instruction
		regionInstructions, harderror = disassemble(info, pc, end, spec.LimitN, disassembleAll, region.Address)
		if harderror != nil {
			return false
		}
		spec.LimitN -= uint64(len(regionInstructions))
		regions = append(regions, DisAsmRegion{
			Region:       region,
			Instructions: regionInstructions,
		})
		return spec.LimitN > 0
	})
	softerrors = append(softerrors, regionsSofterrors...)

	if regionsHarderror != nil {
		return DisAsmResult{}, harderror, softerrors
	}
	if harderror != nil {
		return DisAsmResult{}, harderror, softerrors
	}

	return DisAsmResult{regions}, nil, softerrors
}

func disassembleRegion(spec GadgetSearchSpec, region memaccess.MemoryRegion, info disasm.Info, pc uint64, end uint64, disassembleAll bool) (DisAsmRegion, error) {
	regionInstructions, error := disassemble(info, pc, end, spec.LimitN, disassembleAll, region.Address)
	if error != nil {
		return DisAsmRegion{}, error
	}

	disAsmRegion := DisAsmRegion{
		Region:       region,
		Instructions: regionInstructions,
	}
	return disAsmRegion, nil
}

func disassemble(info disasm.Info, start uint64, end uint64, limit uint64, disassembleAll bool, sectionStart uintptr) ([]disasm.Instruction, error) {
	instructions := make([]disasm.Instruction, 0)
	for pc := start; pc < end && uint64(len(instructions)) < limit; {
		instruction, err := disasm.DecodeInstruction(info, disasm.Ptr(pc))
		if err != nil {
			return instructions, err
		}
		instruction.Address -= disasm.Ptr(sectionStart)
		instructions = append(instructions, *instruction)
		if disassembleAll {
			pc++
		} else {
			pc += uint64(instruction.NumOctets)
		}
	}

	return instructions, nil
}

const (
	readelfOffsetLine  = 1
	readelfOffsetToken = 2
	readelfSizeLine    = 2
	// readelfSizeToken = 0
)
