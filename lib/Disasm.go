package lib

import (
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	"github.com/polyverse/ropoly/lib/types"
)

func Disasm(opcodes []byte, offset types.Addr, start types.Addr, end types.Addr) ([]*types.InstructionInstance, []error) {
	searchStart := start
	if offset > start {
		searchStart = offset
	}
	var instructions []*types.InstructionInstance
	var softerrors []error
	for relativeAddr := int(searchStart - offset); relativeAddr < len(opcodes) && offset + types.Addr(relativeAddr) < end; {
		instruction, err := amd64.InstructionDecoder(opcodes[relativeAddr:])
		if err != nil {
			softerrors = append(softerrors, err)
			relativeAddr += 1
			continue
		}
		instructions = append(instructions, types.MakeInstructionInstance(instruction, offset + types.Addr(relativeAddr)))
		relativeAddr += len(instruction.Octets)
	}
	return instructions, nil
}