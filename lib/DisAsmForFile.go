package lib

func DisAsmForFile(path string) (DisAsmResult, error) {
	instructions, err := diskInstructions(path)
	if err != nil {
		return DisAsmResult{}, err
	}

	return disAsmResult(instructions), err
}
