package lib

func DisAsmForFile(path string, startN uint64, endN uint64, limitN uint64, disassembleAll bool) (DisAsmResult, error) {
	instructions, err := diskInstructions(path, startN, endN, limitN, disassembleAll)
	if err != nil {
		return DisAsmResult{}, err
	}

	return disAsmResult(instructions), err
}
