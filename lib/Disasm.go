package lib

import (
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	"github.com/polyverse/ropoly/lib/types"
)

func Disasm(opcodes []byte, offset types.Addr, start types.Addr, end types.Addr) ([]*types.Instruction, []error) {
	if offset > start {
		start = offset
	}
	var instructions []*types.Instruction
	var softerrors []error
	for relativeAddr := int(start - offset); relativeAddr < len(opcodes) && offset + types.Addr(relativeAddr) < end; {
		instruction, err := amd64.InstructionDecoder(opcodes[relativeAddr:])
		if err != nil {
			softerrors = append(softerrors, err)
			relativeAddr += 1
			continue
		}
		instructions = append(instructions, instruction)
		relativeAddr += len(instruction.Octets)
	}
	return instructions, nil
}