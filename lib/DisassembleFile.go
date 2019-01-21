package lib

import (
	"github.com/polyverse/ropoly/lib/types"
)

func DisassembleFile(path string, start types.Addr, end types.Addr) ([]*types.Instruction, error, []error) {
	b, err := openBinary(path)
	if err != nil {
		return nil, err, nil
	}
	defer b.close()

	var allInstructions []*types.Instruction
	var softerrs []error
	sectionExists, addr, progData, err := b.nextSectionData()
	for sectionExists {
		if err != nil {
			return nil, err, nil
		}
		instructions, errors := Disasm(progData, addr, start, end)
		softerrs = append(softerrs, errors...)
		allInstructions = append(allInstructions, instructions...)
		sectionExists, addr, progData, err = b.nextSectionData()
	}

	return allInstructions, nil, softerrs
}