package lib

import (
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	"github.com/polyverse/ropoly/lib/types"
)

var Prefixes []byte = []byte{
	0xf0,
	0xf3,
	0xf2,
	0x2e,
	0x36,
	0x3e,
	0x26,
	0x64,
	0x65,
	0x66,
	0x67,
}

type byteRange struct {
	min byte
	max byte
}

var TerminatingInstructions [][]byteRange = [][]byteRange {
	{ {0xff, 0xff}, {0x20, 0x27} },
	{ {0xff, 0xff}, {0xe0, 0xe7} },
	{ {0xc3, 0xc3} },
	{ {0xc2, 0xc2}, {0x00, 0xff}, {0x00, 0xff} },
	{ {0xcb, 0xcb} },
	{ {0xca, 0xca}, {0x00, 0xff}, {0x00, 0xff} },
}

func Disasm(opcodes []byte, offset types.Addr, start types.Addr) ([]*types.Instruction, error) {
	var instructions []*types.Instruction
	for relativeAddr := int(start - offset); relativeAddr < len(opcodes); {
		instruction, err := amd64.InstructionDecoder(opcodes[relativeAddr:])
		if err != nil {
			return instructions, err
		}
		instructions = append(instructions, instruction)
		strippedInstruction := stripPrefixBytes(instruction.Octets)
		if isTerminatingInstruction(strippedInstruction) {
			return instructions, nil
		}
		relativeAddr += len(instruction.Octets)
	}
	return instructions, nil
}

func stripPrefixBytes(octets []byte) []byte {
	for hasPrefixByte(octets) {
		octets = octets[1:]
	}
	return octets
}

func hasPrefixByte(octets []byte) bool {
	for _, prefix := range Prefixes {
		if octets[0] == prefix {
			return true
		}
	}
	return false
}

func isTerminatingInstruction(octets []byte) bool {
	for _, terminatingInstruction := range TerminatingInstructions {
		if len(terminatingInstruction) == len(octets) {
			match := true
			for i, br := range terminatingInstruction {
				if octets[i] < br.min || octets[i] > br.max {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}