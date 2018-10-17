package lib

func MemoryDisAsmForPid(pidN int, startN uint64, endN uint64, limitN uint64, disassembleAll bool) (DisAsmResult, error, []error) {
	return DisAsm(GadgetSearchSpec{
		InMemory: true,
		PidN: pidN,
		StartN: startN,
		EndN: endN,
		LimitN: limitN,
	}, disassembleAll)
}
