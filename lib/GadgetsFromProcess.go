package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	"github.com/polyverse/ropoly/lib/gadgets"
	"github.com/polyverse/ropoly/lib/types"
)

func GadgetsFromProcess(pid int, maxLength int, start, end, base types.Addr) (types.GadgetInstances, error, []error) {
	softerrors := []error{}
	proc := process.GetProcess(pid)

	allGadgets := []*types.GadgetInstance{}

	pc := uintptr(start)
	for {
		if pc >= (uintptr(end)) {
			break
		}

		region, harderror2, softerrors2 := memaccess.NextMemoryRegionAccess(proc, uintptr(pc), memaccess.Readable+memaccess.Executable)
		softerrors = append(softerrors, softerrors2...)
		if harderror2 != nil {
			return nil, errors.Wrapf(harderror2, "Error when attempting to access the next memory region for Pid %d.", pid), softerrors
		}

		if region == memaccess.NoRegionAvailable {
			break
		}

		size := region.Size
		if uintptr(end) - pc < uintptr(size) {
			size = uint(uintptr(end) - pc)
		}
		opcodes := make([]byte, size, size)
		harderr3, softerrors3 := memaccess.CopyMemory(proc, pc, opcodes)
		softerrors = append(softerrors, softerrors3...)
		if harderr3 != nil {
			softerrors = append(softerrors, errors.Wrapf(harderr3, "Error when attempting to access the memory contents for Pid %d.", pid))
		}

		foundgadgets, harderr4, softerrors4 := gadgets.Find(opcodes, amd64.GadgetSpecs, amd64.GadgetDecoder, types.Addr(pc), maxLength)
		for _, gadget := range foundgadgets {
			gadget.Address -= base
		}
		softerrors = append(softerrors, softerrors4...)
		if harderr4 != nil {
			return nil, errors.Wrapf(harderr4, "Error when attempting to decode gadgets from the memory region %s for Pid %d.", region.String(), pid), softerrors
		}
		allGadgets = append(allGadgets, foundgadgets...)

		//Make sure we move the Program Counter
		pc = region.Address + uintptr(region.Size)
	}

	return allGadgets, nil, softerrors
}
