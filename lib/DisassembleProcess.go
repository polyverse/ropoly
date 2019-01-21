package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/lib/types"
)

func DisassembleProcess(pid int, start types.Addr) ([]*types.Instruction, error, []error) {
	softerrors := []error{}
	proc := process.GetProcess(pid)

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

		regionStart := types.Addr(region.Address)
		regionEnd := types.Addr(region.Address) + types.Addr(region.Size)

		if start < regionStart {
			break
		}
		if start >= regionStart && start <= regionEnd {
			opcodes := make([]byte, region.Size, region.Size)
			harderr3, softerrors3 := memaccess.CopyMemory(proc, region.Address, opcodes)
			softerrors = append(softerrors, softerrors3...)
			if harderr3 != nil {
				softerrors = append(softerrors, errors.Wrapf(harderr3, "Error when attempting to access the memory contents for Pid %d.", pid))
			}

			instructions, err := Disasm(opcodes, regionStart, start)
			if err != nil {
				softerrors = append(softerrors, err)
			}
			return instructions, nil, softerrors
		}

		//Make sure we move the Program Counter
		pc = region.Address + uintptr(region.Size)
	}

	return nil, errors.New("Could not find region containing start address."), softerrors
}