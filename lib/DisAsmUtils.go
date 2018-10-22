package lib

import (
	"github.com/polyverse/disasm"
)

const (
	readelfOffsetLine = 1
	readelfOffsetToken = 2
	readelfSizeLine = 2
	// readelfSizeToken = 0
)

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