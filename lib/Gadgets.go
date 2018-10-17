package lib

import (
	"github.com/polyverse/disasm"
	"hash/crc32"
	"math"
	"strconv"
	"strings"
)

func gadgetAtIndex(index int, instructions []disasm.Instruction, spec GadgetSearchSpec) (bool, []disasm.Instruction) {
	gadgetInstructions := make([]disasm.Instruction, 0)
	numOctets := uint64(0)
	for i := index; i < len(instructions) && uint64(len(gadgetInstructions)) <= spec.InstructionsN && numOctets < spec.OctetsN; i++ {
		instruction := instructions[i]

		if len(gadgetInstructions) != 0 {
			pos := relativePosition(gadgetInstructions[len(gadgetInstructions)-1], instruction)
			if pos == overlapping {
				continue
			} else if pos == apart {
				break
			}
		}

		numOctets += uint64(instruction.NumOctets)
		if numOctets > spec.OctetsN {
			break
		}

		gadgetInstructions = append(gadgetInstructions, instruction)

		if isControlInstruction(instruction) {
			return true, gadgetInstructions
		}
	}
	return false, gadgetInstructions
}

func gadget(instructions []disasm.Instruction) Gadget {
	octets := make([]byte, 0)
	for i := 0; i < len(instructions); i++ {
		octets = append(octets, instructions[i].Octets...)
	}
	signature := crc32.ChecksumIEEE(octets)
	return Gadget {
		Address:            instructions[0].Address,
		NumInstructions:    len(instructions),
		NumOctets:          len(octets),
		Signature:          Sig((signature / math.MaxUint16) ^ (signature % math.MaxUint16)),
		Instructions:       instructions,
	}
}

func isControlInstruction(instruction disasm.Instruction) bool {
	tokens := strings.Split(instruction.DisAsm, " ")
	mnemonic := tokens[0]
	return controlInstructions[mnemonic]
}

// first must precede second
func relativePosition(first disasm.Instruction, second disasm.Instruction) position {
	firstEnd := disasm.Ptr(first.Address + disasm.Ptr(first.NumOctets))
	if firstEnd == second.Address {
		return adjacent
	} else if firstEnd < second.Address {
		return apart
	} else /* firstEnd > second.Address */ {
		return overlapping
	}
}

func (g *Gadget) String() string {
	sAdr := strconv.FormatUint(uint64(g.Address), 16)
	return "0x" + sAdr
}