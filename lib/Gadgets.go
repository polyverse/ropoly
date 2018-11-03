package lib

import (
	"github.com/polyverse/disasm"
	"hash/crc32"
	"math"
	"strconv"
	"strings"
)

type position int

const (
	adjacent    position = 1
	overlapping position = 2
	apart       position = 3
)

type controlType int

const (
	notControl  controlType = 0
	dontCare    controlType = 1
	gadgetEnd   controlType = 2
	breakGadget controlType = 3
	prefix      controlType = 4
	bad         controlType = 5
)

var controlInstructions = map[string]controlType{
	"jmp":   breakGadget,
	"je":    dontCare,
	"jne":   dontCare,
	"jg":    dontCare,
	"jge":   dontCare,
	"ja":    dontCare,
	"jae":   dontCare,
	"jl":    dontCare,
	"jle":   dontCare,
	"jb":    dontCare,
	"jbe":   dontCare,
	"jo":    dontCare,
	"jno":   dontCare,
	"jz":    dontCare,
	"jnz":   dontCare,
	"js":    dontCare,
	"jns":   dontCare,
	"call":  dontCare,
	"ret":   gadgetEnd,
	"lock":  prefix,
	"rep":   prefix,
	"repe":  prefix,
	"repz":  prefix,
	"repne": prefix,
	"repnz": prefix,
	"(bad)": bad,
}

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

		cType := getControlType(instruction)
		if cType == breakGadget || cType == bad {
			break
		}

		numOctets += uint64(instruction.NumOctets)
		if numOctets > spec.OctetsN {
			break
		}

		gadgetInstructions = append(gadgetInstructions, instruction)

		if cType == gadgetEnd {
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
	return Gadget{
		Address:         instructions[0].Address,
		NumInstructions: len(instructions),
		NumOctets:       len(octets),
		Signature:       Sig((signature / math.MaxUint16) ^ (signature % math.MaxUint16)),
		Instructions:    instructions,
	}
}

func getControlType(instruction disasm.Instruction) controlType {
	tokens := strings.Split(instruction.DisAsm, " ")
	var mnemonic string
	cType := prefix
	for i := 0; cType == prefix && i < len(tokens); i++ {
		mnemonic = tokens[i]
		cType = controlInstructions[mnemonic]
	}
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
