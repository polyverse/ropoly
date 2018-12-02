package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	"github.com/polyverse/ropoly/lib/gadgets"
	"github.com/polyverse/ropoly/lib/types"
)

func GadgetsFromProcess(pid int, maxLength int) (types.GadgetInstances, error, []error) {
	softerrors := []error{}
	proc := process.LinuxProcess(pid)

	allGadgets := []*types.GadgetInstance{}

	pc := uintptr(0)
	for {
		region, harderror2, softerrors2 := memaccess.NextMemoryRegionAccess(proc, uintptr(pc), memaccess.Readable+memaccess.Executable)
		softerrors = append(softerrors, softerrors2...)
		if harderror2 != nil {
			return nil, errors.Wrapf(harderror2, "Error when attempting to access the next memory region for Pid %d.", pid), softerrors
		}

		if region == memaccess.NoRegionAvailable {
			break
		}

		//Make sure we move the Program Counter
		pc = region.Address + uintptr(region.Size)

		opcodes := make([]byte, region.Size, region.Size)
		harderr3, softerrors3 := memaccess.CopyMemory(proc, region.Address, opcodes)
		softerrors = append(softerrors, softerrors3...)
		if harderr3 != nil {
			return nil, errors.Wrapf(harderr3, "Error when attempting to access the memory contents for Pid %d.", pid), softerrors
		}

		foundgadgets, harderr4, softerrors4 := gadgets.Find(opcodes, amd64.GadgetSpecs, amd64.GadgetDecoder, types.Addr(region.Address), maxLength)
		softerrors = append(softerrors, softerrors4...)
		if harderr4 != nil {
			return nil, errors.Wrapf(harderr4, "Error when attempting to decode gadgets from the memory region %s for Pid %d.", region.String(), pid), softerrors
		}
		allGadgets = append(allGadgets, foundgadgets...)
	}

	return allGadgets, nil, softerrors
}
