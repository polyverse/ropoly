package lib

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	"github.com/polyverse/disasm"
)

func instructions(command *exec.Cmd) ([]disasm.Instruction, error) {
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

func parseInstruction(line string) (bool, disasm.Instruction) {
	lineSections := strings.SplitN(line, "\t", 3)
	if len(lineSections) != 3 {
		return false, disasm.Instruction{}
	}
	addressString := strings.Replace(strings.Replace(lineSections[0], " ", "", -1), ":", "", 1)
	address, _ := strconv.ParseInt(addressString, 16, 64)
	bytes := parseBytes(lineSections[1])
	return true, disasm.Instruction {
		Address: disasm.Ptr(address),
		NumOctets: len(bytes),
		Octets: bytes,
		DisAsm: lineSections[2],
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
	return instructions(exec.Command("objdump", "-s", "-d", "-j", ".text", filepath))
}

func disAsmResult(instructions []disasm.Instruction) DisAsmResult {
	return DisAsmResult {
		Instructions: instructions,
	}
}