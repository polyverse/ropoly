package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/lib/types"
)

func SectionsForPid(pid int, start uint64, end uint64) ([]*types.RawSection, error, []error) {
	sections := []*types.RawSection{}

	softerrors := []error{}
	process, harderror1, softerrors1 := process.OpenFromPid(pid)
	if harderror1 != nil {
		return nil, errors.Wrapf(harderror1, "Error occurred when attempting to open Pid %d for disassembly.", pid), softerrors1
	}
	defer process.Close()
	softerrors = append(softerrors, softerrors1...)

	for pc := start; (pc <= end); {
		region, harderror2, softerrors2 := NextReadableExecutableMemoryRegion(process, uintptr(pc))
		if harderror2 != nil {
			return nil, errors.Wrapf(harderror2, "Error when attempting to access the next memory region for Pid %d.", pid), joinerrors(softerrors1, softerrors2)
		}
		softerrors = append(softerrors, softerrors2...)

		if region == memaccess.NoRegionAvailable {
			break
		}

		if pc < uint64(region.Address) {
			pc = uint64(region.Address)
		}

		if pc > end {
			break
		}

		var info disasm.Info
		var bytes []byte // Scope is important here. Unsafe pointers are taken in disasm.InfoInitBytes(). Store must survive next block.

		if pid == 0 {
			info = disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1))
		} else {
			bytes = make([]byte, region.Size, region.Size)
			memaccess.CopyMemory(process, region.Address, bytes)
			info = disasm.InfoInitBytes(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1), bytes)
		}

		regionEnd := uint64((region.Address + uintptr(region.Size)))
		if regionEnd > end {
			regionEnd = end
		}


		sections = append(sections, &types.RawSection{
			Address: region.Address,
			DisAsmInfo: info,
			SectionStart: pc,
			SectionEnd: regionEnd,
		})
		pc = regionEnd
	}

	return sections, nil, softerrors
}

// NextReadableMemoryRegion returns a memory region containing address, or the next readable region after address in
// case addresss is not in a readable region.
//
// If there aren't more regions available the special value NoRegionAvailable is returned.
func NextReadableExecutableMemoryRegion(p process.Process, address uintptr) (region memaccess.MemoryRegion, harderror error, softerrors []error) {
	r1, h1, s1 := memaccess.NextMemoryRegionAccess(p, address, memaccess.Readable+memaccess.Executable)
	for {
		r2, h2, _ := memaccess.NextMemoryRegionAccess(p, r1.Address + uintptr(r1.Size), memaccess.Readable+memaccess.Executable)
		if (h2 != nil) || (r2 == memaccess.NoRegionAvailable) || (r2.Address > r1.Address + uintptr(r1.Size)) {
			break;
		} // if

		r1.Size += r2.Size
	}

	return r1, h1, s1
	// return NextMemoryRegionAccess(p, address, Readable)
}