package lib

import (
	"bytes"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
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

func diskInstructions(filepath string, startN uint64, endN uint64, limitN uint64, disassembleAll bool) ([]DisAsmRegion, error) {
	command := exec.Command("readelf", "--section-details", filepath)
	readelfResult, error := command.Output()
	if error != nil {
		return []DisAsmRegion{}, error
	}

	regions := make([]DisAsmRegion, 0)

	sectionInfo := bytes.Split(readelfResult, []byte("] "))
	for i := 0; i < len(sectionInfo); i++ {
		found, sectionStart, sectionLength := sectionLocation(sectionInfo[i], []byte(".text"))
		if found {
			instructions, error := disassembleFile(filepath, startN, endN, limitN, disassembleAll, sectionStart, sectionLength)
			if error != nil {
				return []DisAsmRegion{}, error
			}

			region := memaccess.MemoryRegion {
				Address: uintptr(sectionStart),
				Size: uint(sectionLength),
				Kind: string(bytes.SplitN(sectionInfo[i], []byte("\n"), 2)[0]),
			}

			regions = append(regions, DisAsmRegion {
				Instructions: instructions,
				Region: region,
			})
		}
	}

	if len(regions) == 0 {
		return []DisAsmRegion{}, errors.New(".text section not found or could not be parsed")
	}
	return regions, nil
}

const (
	readelfOffsetLine = 1
	readelfOffsetToken = 2
	readelfSizeLine = 2
	// readelfSizeToken = 0
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
	instructions, err := disassemble(info, start, end, limitN, disassembleAll, uintptr(sectionStart))
	return instructions, err
}

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

// Returns found gadgets, index of first instruction of last gadget
func gadgets(instructions []disasm.Instruction, spec GadgetSearchSpec) ([]Gadget, int) {
	gadgets := make([]Gadget, 0)

	foundEarly := map[int]*Gadget{}

	var index int
	for index = 0; index < len(instructions) && uint64(len(gadgets)) < spec.LimitN; index++ {
		if foundEarly[index] == nil {
			found, gadgetInstructions := gadgetAtIndex(index, instructions, spec)
			if found {
				gadgets = append(gadgets, gadget(gadgetInstructions))
				for i := 1; i < len(gadgetInstructions) && uint64(len(gadgets) + len(foundEarly)) < spec.LimitN; i++ {
					subgadgetInstructions := gadget(gadgetInstructions[i:])
					foundEarly[i] = &subgadgetInstructions
				}
			}
		} else {
			gadgets = append(gadgets, *foundEarly[index])
			delete(foundEarly, index)
		}
	}

	return gadgets, index
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
