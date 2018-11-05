package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
)

func GadgetsFromProcess(pid int, maxLength int) ([]*disasm.Gadget, error, []error) {
	softerrors := []error{}
	process, harderror1, softerrors1 := process.OpenFromPid(pid)
	if harderror1 != nil {
		return nil, errors.Wrapf(harderror1, "Error occurred when attempting to open Pid %d for disassembly.", pid), softerrors1
	}
	defer process.Close()
	softerrors = append(softerrors, softerrors1...)

	allGadgets := []*disasm.Gadget{}

	pc := uintptr(0)
	for {
		region, harderror2, softerrors2 := NextReadableExecutableMemoryRegion(process, uintptr(pc))
		if harderror2 != nil {
			return nil, errors.Wrapf(harderror2, "Error when attempting to access the next memory region for Pid %d.", pid), joinerrors(softerrors1, softerrors2)
		}
		softerrors = append(softerrors, softerrors2...)

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
			memaccess.CopyMemory(process, region.Address, bytes)
			info = disasm.InfoInitBytes(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1), bytes)
		}
		gadgets, errs := info.GetAllGadgets(2, maxLength, 0, 100)
		allGadgets = append(allGadgets, gadgets...)
		softerrors = append(softerrors, errs...)
	}

	return allGadgets, nil, softerrors
}

// NextReadableExecutableMemoryRegion returns a memory region containing address, or the next readable+executable region
// after address in case addresss is not in a readable+executable region.
//
// If there aren't more regions available the special value NoRegionAvailable is returned.
func NextReadableExecutableMemoryRegion(p process.Process, address uintptr) (region memaccess.MemoryRegion, harderror error, softerrors []error) {
	r1, h1, s1 := memaccess.NextMemoryRegionAccess(p, address, memaccess.Readable+memaccess.Executable)
	for {
		r2, h2, _ := memaccess.NextMemoryRegionAccess(p, r1.Address+uintptr(r1.Size), memaccess.Readable+memaccess.Executable)
		if (h2 != nil) || (r2 == memaccess.NoRegionAvailable) || (r2.Address > r1.Address+uintptr(r1.Size)) {
			break
		} // if

		r1.Size += r2.Size
	}

	return r1, h1, s1
	// return NextMemoryRegionAccess(p, address, Readable)
}
