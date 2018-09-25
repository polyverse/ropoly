package lib

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

const objdumpAddressStart = 2
const objdumpInstructionStart = 32
const addressDisplaySpace = 12

type binary struct {
	Addresses []int64
	Instructions []string
}

func instructions(command *exec.Cmd) (binary, error) {
	ret := binary{
		Addresses: make([]int64, 0),
		Instructions: make([]string, 0),
	}

	objdumpResult, error := command.Output()
	if error != nil {
		return ret, error
	}
	objdumpDisasm := string(bytes.Split(bytes.Split(objdumpResult, []byte("Disassembly of section .text:\n\n"))[1], []byte("<_start>:\n"))[1])
	objdumpLines := strings.Split(objdumpDisasm, "\n")
	for i := 0; i < len(objdumpLines); i++ {
		lineSections := strings.SplitN(objdumpLines[i], "\t", 3)
		if len(lineSections) == 3 {
			addressString := strings.Replace(strings.Replace(lineSections[0], " ", "", -1), ":", "", 1)
			address, _ := strconv.ParseInt(addressString, 16, 64)
			instruction := lineSections[2]
			ret.Addresses = append(ret.Addresses, address)
			ret.Instructions = append(ret.Instructions, instruction)
		}
	}

	return ret, error
}

func diskInstructions(filepath string) (binary, error) {
	return instructions(exec.Command("objdump", "-s", "-d", "-j", ".text", filepath))
}

func memoryInstructions(pid int) (binary, error) {
	return instructions(exec.Command("objdump", "-s", "-d", "/proc/"+strconv.Itoa(pid)+"/mem"))
}

func disAsmResult(bin binary) DiskDisAsmResult {
	ret := DiskDisAsmResult{
		Instructions: make([]string, 0),
	}

	for i := 0; i < len(bin.Addresses); i++ {
		line := strconv.Itoa(int(bin.Addresses[i]))
		line += strings.Repeat(" ", addressDisplaySpace - len(line))
		line += bin.Instructions[i]
		ret.Instructions = append(ret.Instructions, line)
	}

	return ret
}

func instructionCounts(bin binary) map[string]int64 {
	ret := map[string]int64{}
	for i := 0; i < len(bin.Addresses); i++ {
		_, exists := ret[bin.Instructions[i]]
		if exists {
			ret[bin.Instructions[i]]++
		} else {
			ret[bin.Instructions[i]] = 0
		}
	}
	return ret
}