package lib

func DisAsmForFile(path string, startN uint64, endN uint64, limitN uint64, disassembleAll bool) (DisAsmResult, error, []error) {
	return DisAsm(GadgetSearchSpec{
		InMemory: false,
		Filepath: path,
		StartN: startN,
		EndN: endN,
		LimitN: limitN,
	}, disassembleAll)
}
