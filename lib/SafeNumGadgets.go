package lib

const safeNumInstructions = 100000

func SafeNumGadgets(instructionsN uint64) uint64 {
	if safeNumInstructions/instructionsN > 1 {
		return safeNumInstructions / instructionsN
	} else {
		return 1
	}
}