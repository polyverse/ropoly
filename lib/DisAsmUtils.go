package lib

import (
	"bytes"
	"github.com/polyverse/disasm"
	"os/exec"
	"strconv"
	"strings"
	"errors"
	"os"
	"hash/crc32"
	"math"
)

type position int

const (
	adjacent    position = 1
	overlapping position = 2
	apart       position = 3
)

const section = ".text"

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

func diskInstructions(filepath string, startN uint64, endN uint64, limitN uint64, disassembleAll bool) ([]disasm.Instruction, error) {
	command := exec.Command("readelf", "--section-details", filepath)
	readelfResult, error := command.Output()
	if error != nil {
		return []disasm.Instruction{}, error
	}

	sectionInfo := bytes.Split(readelfResult, []byte("] "))
	for i := 0; i < len(sectionInfo); i++ {
		found, sectionStart, sectionLength := sectionLocation(sectionInfo[i], []byte(".text"))
		if found {
			return disassembleFile(filepath, startN, endN, limitN, disassembleAll, sectionStart, sectionLength)
		}
	}
	return make([]disasm.Instruction, 0), errors.New(".text section not found or could not be parsed")
}

const (
	readelfOffsetLine = 1
	readelfOffsetToken = 2
	readelfSizeLine = 2
	//readelfSizeToken = 0
)

func sectionLocation(header []byte, target []byte) (bool, uint64, uint64) {
	if len(header) < len(target) {
		return false, 0, 0
	}
	for i := 0; i < len(target); i++ {
		if header[i] != target[i] {
			return false, 0, 0
		}
	}

	headerLines := bytes.Split(header, []byte("\n"))

	offsetQueue := noEmptyByteArraysQueue {
		Items: bytes.Split(headerLines[readelfOffsetLine], []byte(" ")),
		Index: 0,
	}
	for i := 0; i < readelfOffsetToken; i++ {
		dequeueByteArray(&offsetQueue)
	}
	offset, err := strconv.ParseUint(string(dequeueByteArray(&offsetQueue)), 16, 64)
	if err != nil {
		return false, 0, 0
	}

	sizeQueue := noEmptyByteArraysQueue {
		Items: bytes.Split(headerLines[readelfSizeLine], []byte(" ")),
		Index: 0,
	}
	size, err := strconv.ParseUint(string(dequeueByteArray(&sizeQueue)), 16, 64)
	if err != nil {
		return false, 0, 0
	}

	return true, offset, size
}

func disassembleFile(filepath string, startN uint64, endN uint64, limitN uint64, disassembleAll bool, sectionStart uint64, sectionLength uint64) ([]disasm.Instruction, error) {
	binary := make([]byte, sectionLength)
	file, err := os.Open(filepath)
	if err != nil {
		return []disasm.Instruction{}, err
	}
	file.ReadAt(binary, int64(sectionStart))
	file.Close()

	start := startN
	if start < sectionStart {
		start = sectionStart
	}

	end := endN
	if end > sectionStart + sectionLength {
		end = sectionStart + sectionLength
	}

	info := disasm.InfoInitBytes(disasm.Ptr(sectionStart), disasm.Ptr(sectionStart + sectionLength - 1), binary)
	instructions, err := disassemble(info, start, end, limitN, disassembleAll)
	return instructions, err
}

func disassemble(info disasm.Info, start uint64, end uint64, limit uint64, disassembleAll bool) ([]disasm.Instruction, error) {
	instructions := make([]disasm.Instruction, 0)
	for pc := start; pc < end && uint64(len(instructions)) < limit; {
		instruction, err := disasm.DecodeInstruction(info, disasm.Ptr(pc))
		if err != nil {
			return instructions, err
		}
		instructions = append(instructions, *instruction)
		if disassembleAll {
			pc++
		} else {
			pc += uint64(instruction.NumOctets)
		}
	}
	return instructions, nil
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
	gadgetInstructions := make([]disasm.Instruction, 0)

	numOctets := 0
	for length := 0; length < maxLength && instructionIndex-length >= 0; length++ {
		index := instructionIndex - length
		instruction := instructions[index]

		if length != 0 {
			if isControlInstruction(instruction) {
				break
			}

			pos := relativePosition(instruction, gadgetInstructions[0])
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

		gadgetInstructions = append([]disasm.Instruction{instruction}, gadgetInstructions...)

		ret = append([]Gadget{gadget(gadgetInstructions)}, ret...)
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
