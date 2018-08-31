package lib

import (
	"fmt"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
)

func GadgetsInMemoryForPid(pidN int, instructions string, startN uint64, endN uint64, limitN uint64, instructionsN uint64, octetsN uint64) (GadgetResult, error, []error) {
	softerrors := []error{}
	process, harderror1, softerrors1 := process.OpenFromPid(pidN)
	softerrors = append(softerrors, softerrors1...)
	if harderror1 != nil {
		return GadgetResult{}, harderror1, softerrors
	} // if
	defer process.Close()

	var numGadgets int
	var gadgetResult GadgetResult

	for pc := startN; (pc <= endN) && (numGadgets < int(limitN)); {
		region, harderror2, softerrors2 := memaccess.NextMemoryRegionAccess(process, uintptr(pc), memaccess.Readable+memaccess.Executable)
		softerrors = append(softerrors, softerrors2...)
		if harderror2 != nil {
			return GadgetResult{}, harderror2, softerrors
		} // if

		if region == memaccess.NoRegionAvailable {
			break
		} // if

		if pc < uint64(region.Address) {
			pc = uint64(region.Address)
		} // if

		if pc > endN {
			break
		} // if

		var info disasm.Info
		var bytes []byte // Scope is important here. Unsafe pointers are taken in disasm.InfoInitBytes(). Store must survive next block.

		if pidN != 0 {
			bytes = make([]byte, region.Size, region.Size)
			memaccess.CopyMemory(process, region.Address, bytes)
			info = disasm.InfoInitBytes(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1), bytes)
		} else {
			info = disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1))
		} // else

		fmt.Printf("Searching region: %v\n", region)

		for ; (pc <= endN) && pc < uint64((region.Address+uintptr(region.Size))) && (numGadgets < int(limitN)); pc++ {
			if (pc % 0x100000) == 0 {
				fmt.Printf("pc: %x\n", pc)
			} // if

			gadget, err := disasm.DecodeGadget(info, disasm.Ptr(pc), int(instructionsN), int(octetsN))
			if err == nil {
				gadgetResult.Gadgets = append(gadgetResult.Gadgets, *gadget)
				numGadgets++
			} // if
		} // for
	} // for

	return gadgetResult, nil, softerrors
}

func GadgetFingerprintssInMemoryForPid(pidN int, instructions string, startN uint64, endN uint64, limitN uint64, instructionsN uint64, octetsN uint64) (FingerprintResult, error, []error) {

	fr := FingerprintResult{}
	fr.Gadgets = []string{}

	gadgetResult, harderror, softerrors := GadgetsInMemoryForPid(pidN, instructions, startN, endN, limitN, instructionsN, octetsN)
	if harderror != nil {
		return fr, harderror, softerrors
	}

	for _, gadget := range gadgetResult.Gadgets {
		fr.Gadgets = append(fr.Gadgets, gadget.String())
	}

	return fr, harderror, softerrors
}
