package lib

import (
	//"github.com/polyverse/disasm"
	"math"
	"errors"
)

// TODO
// Returns found gadgets, remaining instructions to search, hard error, soft errors
func Gadgets(instructions *[]DisAsmRegion, spec GadgetSearchSpec) (GadgetResult, *[]DisAsmRegion, error, []error) {
	/*var harderror error
	var softerrors []error
	if instructions == nil {
		instructions = new([]DisAsmRegion)
		*instructions, harderror, softerrors = getInstructions(spec.InMemory, spec.PidN, spec.Filepath, spec.StartN, spec.EndN)
		if harderror != nil {
			return GadgetResult{}, instructions, harderror, softerrors
		}
	}

	gadgetsFound, lastRegionIndex, lastInstructionIndex := gadgets(*instructions, spec)
	newInstructions := len(*instructions[])
	newInstructions = (*instructions)[lastIndex:]
	return GadgetResult{
		Gadgets: gadgetsFound,
	}, &newInstructions, nil, softerrors*/
	return GadgetResult{}, nil, errors.New("Gadgets is broken right now."), []error{}
}

func getInstructions(inMemory bool, pidN int, filepath string, startN uint64, endN uint64) ([]DisAsmRegion, error, []error) {
	if inMemory {
		return memoryInstructions(pidN, startN, endN)
	} else {
		ret, err := diskInstructions(filepath, startN, endN, endN - startN, true)
		return ret, err, make([]error, 0)
	}
}

func memoryInstructions(pidN int, startN uint64, endN uint64) ([]DisAsmRegion, error, []error) {
	instructionLimit := endN - startN
	if instructionLimit > math.MaxInt32 {
		instructionLimit = math.MaxInt32
	}
	disasmResult, harderror, softerrors := MemoryDisAsmForPid(pidN, startN, endN, uint64(instructionLimit), true)
	if harderror != nil {
		return []DisAsmRegion{}, harderror, softerrors
	}
	instructions := disasmResult.Regions
	return instructions, harderror, softerrors
}