package lib

func DisAsmForFile(path string) (DiskDisAsmResult, error) {
	instructions, err := diskInstructions(path)
	if err != nil {
		return DiskDisAsmResult{}, err
	}

	return disAsmResult(instructions), err
}