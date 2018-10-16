package lib

import (
	//"github.com/polyverse/disasm"
	"errors"
)

func Fingerprint(spec GadgetSearchSpec) (FingerprintResult, error, []error) {
	/*fingerprint := map[Sig][]disasm.Ptr{}
	harderror, softerrors := OperateOnGadgets(spec, func(gadgetResult GadgetResult, firstTime bool, lastTime bool)(error) {
		for i := 0; i < len(gadgetResult.Gadgets); i++ {
			gadget := gadgetResult.Gadgets[i]
			fingerprint[gadget.Signature] = append(fingerprint[gadget.Signature], gadget.Address)
		}
		return nil
	})
	return FingerprintResult {
		Gadgets: fingerprint,
	}, harderror, softerrors*/
	return FingerprintResult{}, errors.New("Fingerprint is broken."), []error{}
}