package lib

import (
	"errors"
	"github.com/polyverse/disasm"
)

func OperateOnGadgets(spec GadgetSearchSpec, operation func(GadgetResult, bool, bool)(error)) (error, []error) {
	perWriteSpec := spec
	gadgetsPerWrite := SafeNumGadgets(spec.InstructionsN)
	perWriteSpec.LimitN = gadgetsPerWrite
	var disasmInstructions []disasm.Instruction
	firstTime := true
	var numGadgetsReturned uint64
	var numGadgetsTotal uint64 = 0
	var softerrors []error
	for numGadgetsTotal < spec.LimitN && (firstTime || numGadgetsReturned == gadgetsPerWrite) {
		var gadgetResult GadgetResult
		var harderror error
		var gadgetsSofterrors []error
		gadgetResult, disasmInstructions, harderror, gadgetsSofterrors = Gadgets(disasmInstructions, perWriteSpec)
		softerrors = append(softerrors, gadgetsSofterrors...)
		if harderror != nil {
			var errorMessage string
			defer func() {
				if recover() != nil {
					errorMessage = "Cannot read error message."
				}
			}()
			errorMessage = harderror.Error()
			return errors.New(errorMessage), softerrors
		}

		numGadgetsReturned = uint64(len(gadgetResult.Gadgets))
		numGadgetsTotal += numGadgetsReturned
		lastTime := numGadgetsReturned < gadgetsPerWrite || numGadgetsTotal >= spec.LimitN

		opHarderror:= operation(gadgetResult, firstTime, lastTime)
		if opHarderror != nil {
			return opHarderror, softerrors
		}

		firstTime = false
	}

	return nil, softerrors
}