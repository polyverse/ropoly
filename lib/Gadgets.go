package lib

import (
	"math"
	"github.com/polyverse/disasm"
)

func Gadgets(instructions []disasm.Instruction, inMemory bool, pidN int, filepath string, startN uint64, endN uint64, limitN uint64, instructionsN uint64, octetsN uint64) (GadgetResult, []disasm.Instruction, error, []error) {
	var harderror error
	var softerrors []error
	if instructions == nil {
		instructions, harderror, softerrors = getInstructions(inMemory, pidN, filepath, startN, endN)
		if harderror != nil {
			return GadgetResult{}, instructions, harderror, softerrors
		}
	}

	return GadgetResult {
		Gadgets: gadgets(instructions, int(instructionsN), int(octetsN), int(limitN)),
	}, instructions, nil, softerrors
}

func getInstructions(inMemory bool, pidN int, filepath string, startN uint64, endN uint64) ([]disasm.Instruction, error, []error) {
	if inMemory {
		return memoryInstructions(pidN, startN, endN)
	} else {
		ret, err := diskInstructions(filepath)
		return ret, err, make([]error, 0)
	}
}

func memoryInstructions(pidN int, startN uint64, endN uint64) ([]disasm.Instruction, error, []error) {
	instructionLimit := endN - startN
	if instructionLimit > math.MaxInt32 {
		instructionLimit = math.MaxInt32
	}
	disasmResult, harderror, softerrors := MemoryDisAsmForPid(pidN, startN, endN, uint64(instructionLimit))
	if harderror != nil {
		return make([]disasm.Instruction, 0), harderror, softerrors
	}
	instructions := disasmResult.Instructions
	return instructions, harderror, softerrors
}