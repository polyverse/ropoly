package lib

import(
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/disasm"
)

func DisAsm(spec GadgetSearchSpec, disassembleAll bool) (DisAsmResult, error, []error) {
	var harderror error
	var softerrors []error
	var regions []DisAsmRegion

	regionsHarderror, regionsSofterrors := OperateOnRegions(spec, func(region memaccess.MemoryRegion, info disasm.Info, pc uint64, end uint64)bool {
		var regionInstructions []disasm.Instruction
		regionInstructions, harderror = disassemble(info, pc, end, spec.LimitN, disassembleAll, region.Address)
		if harderror != nil {
			return false
		}
		spec.LimitN -= uint64(len(regionInstructions))
		regions = append(regions, DisAsmRegion {
			Region: region,
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

	disAsmRegion := DisAsmRegion {
		Region: region,
		Instructions: regionInstructions,
	}
	return disAsmRegion, nil
}