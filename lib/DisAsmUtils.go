package lib

import (
	"bytes"
	"github.com/polyverse/disasm"
	"os/exec"
	"strconv"
	"strings"
)

type position int

const (
	adjacent    position = 1
	overlapping position = 2
	apart       position = 3
)

var controlInstructions = map[string]bool{
	"jmp":    true,
	"je":     true,
	"jne":    true,
	"jg":     true,
	"jge":    true,
	"ja":     true,
	"jae":    true,
	"jl":     true,
	"jle":    true,
	"jb":     true,
	"jbe":    true,
	"jo":     true,
	"jno":    true,
	"jz":     true,
	"jnz":    true,
	"js":     true,
	"jns":    true,
	"call":   true,
	"ret":    true,
	"loop":   true,
	"loopcc": true,
}

func parseInstruction(line string) (bool, disasm.Instruction) {
	lineSections := strings.SplitN(line, "\t", 3)
	if len(lineSections) != 3 {
		return false, disasm.Instruction{}
	}
	addressString := strings.Replace(strings.Replace(lineSections[0], " ", "", -1), ":", "", 1)
	address, _ := strconv.ParseInt(addressString, 16, 64)
	bytes := parseBytes(lineSections[1])
	return true, disasm.Instruction{
		Address:   disasm.Ptr(address),
		NumOctets: len(bytes),
		Octets:    bytes,
		DisAsm:    lineSections[2],
	}
}

func parseBytes(line string) []byte {
	ret := make([]byte, 0)
	tokens := strings.Split(line, " ")
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token != "" {
			byteValue, _ := strconv.ParseInt(token, 16, 64)
			ret = append(ret, byte(byteValue))
		}
	}
	return ret
}

func diskInstructions(filepath string) ([]disasm.Instruction, error) {
	command := exec.Command("objdump", "-s", "-d", "-j", ".text", filepath)

	ret := make([]disasm.Instruction, 0)

	objdumpResult, error := command.Output()
	if error != nil {
		return ret, error
	}
	objdumpDisasm := string(bytes.Split(objdumpResult, []byte("Disassembly of section .text:\n\n"))[1])
	objdumpLines := strings.Split(objdumpDisasm, "\n")
	for i := 0; i < len(objdumpLines); i++ {
		success, instruction := parseInstruction(objdumpLines[i])
		if success {
			ret = append(ret, instruction)
		}
	}

	return ret, error
}

func disAsmResult(instructions []disasm.Instruction) DisAsmResult {
	return DisAsmResult{
		Instructions: instructions,
	}
}

func gadgets(instructions []disasm.Instruction, maxLength int, maxOctets int, limit int) ([]Gadget, int) {
	ret := make([]Gadget, 0)

	lastStartingIndex := 0
	for i := 0; i < len(instructions) && len(ret) < limit; i++ {
		if isControlInstruction(instructions[i]) {
			var gadgets []Gadget
			gadgets, lastStartingIndex = gadgetsEndingWith(i, instructions, maxLength, maxOctets, limit-len(ret))
			ret = append(ret, gadgets...)
		}
	}

	return ret, lastStartingIndex
}

func gadgetsEndingWith(instructionIndex int, instructions []disasm.Instruction, maxLength int, maxOctets int, limit int) ([]Gadget, int) {
	ret := make([]Gadget, 0)
	startingIndices := make([]int, 0)

	numOctets := 0
	for length := 0; length < maxLength && instructionIndex-length >= 0; length++ {
		index := instructionIndex - length
		instruction := instructions[index]

		if length != 0 {
			if isControlInstruction(instruction) {
				break
			}

			pos := relativePosition(instruction, instructions[index+1])
			if pos == overlapping {
				continue
			} else if pos == apart {
				break
			}
		}

		numOctets += instruction.NumOctets
		if numOctets > maxOctets {
			break
		}

		gadgetInstructions := instructions[instructionIndex-length : instructionIndex+1]
		ret = append([]Gadget{Gadget{
			Address:         gadgetInstructions[0].Address,
			NumInstructions: len(gadgetInstructions),
			NumOctets:       numOctets,
			Instructions:    gadgetInstructions,
		}}, ret...)
		startingIndices = append(startingIndices, index)

		if len(ret) > limit {
			ret = ret[:len(ret)-1]
			startingIndices = startingIndices[1:]
		}
	}

	if len(startingIndices) == 0 {
		return ret, 0
	} else {
		return ret, startingIndices[0] + 1
	}
}

func isControlInstruction(instruction disasm.Instruction) bool {
	tokens := strings.Split(instruction.DisAsm, " ")
	pneumonic := tokens[0]
	return controlInstructions[pneumonic]
}

// first must precede second
func relativePosition(first disasm.Instruction, second disasm.Instruction) position {
	firstEnd := disasm.Ptr(int(first.Address) + first.NumOctets)
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
