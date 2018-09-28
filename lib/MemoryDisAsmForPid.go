package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
)

func MemoryDisAsmForPid(pidN int, startN uint64, endN uint64, limitN uint64) (DisAsmResult, error, []error) {
	softerrors := []error{}
	process, harderror1, softerrors1 := process.OpenFromPid(int(pidN))
	if harderror1 != nil {
		/*DEBUG*/ println(harderror1.Error())
		return DisAsmResult{}, harderror1, softerrors1
	} // if
	defer process.Close()
	softerrors = append(softerrors, softerrors1...)

	var instructions []disasm.Instruction

	for pc := startN; (pc <= endN) && (len(instructions) < int(limitN)); {
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

		for (pc <= endN) && pc < uint64((region.Address+uintptr(region.Size))) && (len(instructions) < int(limitN)) {
			instruction, harderror3 := disasm.DecodeInstruction(info, disasm.Ptr(pc))
			if harderror3 != nil {
				return DisAsmResult{}, harderror3, joinerrors(softerrors1, softerrors2)
			} // if

			instructions = append(instructions, *instruction)
			pc = pc + uint64(instruction.NumOctets)
		} // for
	} // for

	disAsmResult := DisAsmResult{Instructions: instructions}
	return disAsmResult, nil, joinerrors(softerrors1, softerrors)
}
