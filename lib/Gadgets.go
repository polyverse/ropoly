package lib

import (
	"github.com/polyverse/disasm"
	"math"
)

func Gadgets(instructions []disasm.Instruction, inMemory bool, pidN int, filepath string, startN uint64, endN uint64, limitN uint64, instructionsN uint64, octetsN uint64) (GadgetResult, []disasm.Instruction, int, error, []error) {
	var harderror error
	var softerrors []error
	if instructions == nil {
		instructions, harderror, softerrors = getInstructions(inMemory, pidN, filepath, startN, endN)
		if harderror != nil {
			return GadgetResult{}, instructions, 0, harderror, softerrors
		}
	}

	gadgetsFound, count := gadgets(instructions, int(instructionsN), int(octetsN), int(limitN))
	return GadgetResult{
		Gadgets: gadgetsFound,
	}, instructions, count, nil, softerrors
}

func getInstructions(inMemory bool, pidN int, filepath string, startN uint64, endN uint64) ([]disasm.Instruction, error, []error) {
	if inMemory {
		return memoryInstructions(pidN, startN, endN)
	} else {
		ret, err := diskInstructions(filepath, startN, endN, endN - startN, true)
		return ret, err, make([]error, 0)
	}
}

func memoryInstructions(pidN int, startN uint64, endN uint64) ([]disasm.Instruction, error, []error) {
	instructionLimit := endN - startN
	if instructionLimit > math.MaxInt32 {
		instructionLimit = math.MaxInt32
	}
	disasmResult, harderror, softerrors := MemoryDisAsmForPid(pidN, startN, endN, uint64(instructionLimit), true)
	if harderror != nil {
		return make([]disasm.Instruction, 0), harderror, softerrors
	}
	instructions := disasmResult.Instructions
	return instructions, harderror, softerrors
}