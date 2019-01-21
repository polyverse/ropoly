package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/types"
)

func DisassembleFile(path string, start types.Addr) ([]*types.Instruction, error, []error) {
	b, err := openBinary(path)
	if err != nil {
		return nil, err, nil
	}
	defer b.close()

	var softerrs []error
	sectionExists, addr, progData, err := b.nextSectionData()
	for sectionExists {
		if err != nil {
			return nil, err, nil
		}
		if start < addr {
			break
		}
		if start >= addr && start <= addr + types.Addr(len(progData)) {
			instructions, err := Disasm(progData, addr, start)
			if err != nil {
				softerrs = append(softerrs, err)
			}
			return instructions, nil, softerrs
		}
		sectionExists, addr, progData, err = b.nextSectionData()
	}

	return nil, errors.New("Executable section containing starting address does not exist."), softerrs
}