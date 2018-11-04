package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/ropoly/lib/types"
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

func disassembleRegion(region memaccess.MemoryRegion, info disasm.Info, limit uint64, pc uint64, end uint64, disassembleAll bool) (*types.MemoryRegionDisAsm, error) {
	regionInstructions, err := disassemble(info, pc, end, limit, disassembleAll, region.Address)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to disassemble Region %v", region.String())
	}

	return &types.MemoryRegionDisAsm{
		Region:       region,
		Instructions: regionInstructions,
	}, nil
}

func disassemble(info disasm.Info, start uint64, end uint64, limit uint64, disassembleAll bool, sectionStart uintptr) ([]disasm.Instruction, error) {
	instructions := []disasm.Instruction{}
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
			pc += uint64(len(instruction.Octets))
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
