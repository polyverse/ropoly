package lib

import (
	"github.com/polyverse/disasm"
	"math"
)

// Returns found gadgets, remaining instructions to search, hard error, soft errors
func Gadgets(instructions []disasm.Instruction, spec GadgetSearchSpec) (GadgetResult, []disasm.Instruction, error, []error) {
	var harderror error
	var softerrors []error
	if len(instructions) == 0 {
		instructions, harderror, softerrors = getInstructions(spec.InMemory, spec.PidN, spec.Filepath, spec.StartN, spec.EndN)
		if harderror != nil {
			return GadgetResult{}, instructions, harderror, softerrors
		}
	}

	gadgetsFound, lastIndex := gadgets(instructions, spec)
	return GadgetResult{
		Gadgets: gadgetsFound,
	}, instructions[lastIndex:], nil, softerrors
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