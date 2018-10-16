package lib

import (
	//"bytes"
	"github.com/polyverse/disasm"
	//"github.com/polyverse/masche/memaccess"
	//"os/exec"
	"strconv"
	"strings"
	//"errors"
	"os"
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

/*func diskInstructions(filepath string, startN uint64, endN uint64, limitN uint64, disassembleAll bool) ([]DisAsmRegion, error) {
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
}*/

const (
	readelfOffsetLine = 1
	readelfOffsetToken = 2
	readelfSizeLine = 2
	// readelfSizeToken = 0
)

func disassembleFile(file *os.File, startN uint64, endN uint64, limitN uint64, disassembleAll bool, sectionStart uint64, sectionLength uint64) ([]disasm.Instruction, error) {
	binary := make([]byte, sectionLength)
	file.ReadAt(binary, int64(sectionStart))

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