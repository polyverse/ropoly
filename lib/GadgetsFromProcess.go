package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
	"github.com/prometheus/common/log"
)

func GadgetsFromProcess(pid int, maxLength int) ([]*disasm.Gadget, error, []error) {
	softerrors := []error{}
	proc := process.LinuxProcess(pid)

	allGadgets := []*disasm.Gadget{}

	pc := uintptr(0)
	for {
		region, harderror2, softerrors2 := memaccess.NextMemoryRegionAccess(proc, uintptr(pc), memaccess.Readable+memaccess.Executable)
		softerrors = append(softerrors, softerrors2...)
		if harderror2 != nil {
			return nil, errors.Wrapf(harderror2, "Error when attempting to access the next memory region for Pid %d.", pid), softerrors
		}
		log.Debugf("Under Pid %d, Found executable memory region %+v", pid, region)

		if region == memaccess.NoRegionAvailable {
			break
		}

		//Make sure we move the Program Counter
		pc = region.Address + uintptr(region.Size)

		var info disasm.Info
		if pid == 0 {
			info = disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1))
		} else {
			bytes := make([]byte, region.Size, region.Size)
			harderr3, softerrors3 := memaccess.CopyMemory(proc, region.Address, bytes)
			if harderr3 != nil {
				return nil, errors.Wrapf(harderr3, "Error when attempting to access the memory contents for Pid %d.", pid), softerrors
			}
			softerrors = append(softerrors, softerrors3...)
			info = disasm.InfoInitBytes(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1), bytes)
		}
		gadgets, errs := info.GetAllGadgets(2, maxLength, 0, 100)
		allGadgets = append(allGadgets, gadgets...)
		softerrors = append(softerrors, errs...)
	}

	return allGadgets, nil, softerrors
}
