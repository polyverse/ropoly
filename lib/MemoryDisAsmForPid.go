package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
)

func MemoryDisAsmForPid(pidN int, startN uint64, endN uint64, limitN uint64, disassembleAll bool) (DisAsmResult, error, []error) {
	softerrors := []error{}
	process, harderror1, softerrors1 := process.OpenFromPid(int(pidN))
	if harderror1 != nil {
		/*DEBUG*/ println(harderror1.Error())
		return DisAsmResult{}, harderror1, softerrors1
	} // if
	defer process.Close()
	softerrors = append(softerrors, softerrors1...)

	var regions []DisAsmRegion
	numInstructions := 0

	for pc := startN; (pc <= endN) && (numInstructions < int(limitN)); {
		region, harderror2, softerrors2 := memaccess.NextMemoryRegionAccess(process, uintptr(pc), memaccess.Readable+memaccess.Executable)
		if harderror2 != nil {
			return DisAsmResult{}, harderror2, joinerrors(softerrors1, softerrors2)
		} // if
		softerrors = append(softerrors, softerrors2...)

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

		end := uint64((region.Address+uintptr(region.Size)))
		if end > endN {
			end = endN
		}

		regionInstructions, harderror3 := disassemble(info, pc, end, limitN, disassembleAll, region.Address)
		if harderror3 != nil {
			return DisAsmResult{}, harderror3, joinerrors(softerrors1, softerrors2)
		}
		numInstructions += len(regionInstructions)
		regions = append(regions, DisAsmRegion {
			Region: region,
			Instructions: regionInstructions,
		})
		pc = end
	} // for

	disAsmResult := DisAsmResult{Regions: regions}
	return disAsmResult, nil, joinerrors(softerrors1, softerrors)
}
