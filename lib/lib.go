package lib

import (
	"debug/elf"
	"github.com/pkg/errors"
	"github.com/polyverse/disasm"
)

func GadgetsFromExecutable(path string, maxLength int) ([]*disasm.Gadget, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "Error opening ELF file %s", path)
	}

	allGadgets := []*disasm.Gadget{}

	for _, section := range file.Sections {
		if section.Type == elf.SHT_PROGBITS {
			progData, err := section.Data()
			if err != nil {
				return nil, errors.Wrapf(err, "Unable to read data from section in ELF file %s", file)
			}
			info := disasm.InfoInitBytes(disasm.Ptr(section.Addr), disasm.Ptr(section.Addr+section.Size-1), progData)
			gadgets, _ := info.GetAllGadgets(2, maxLength, 0, 100)
			allGadgets = append(allGadgets, gadgets...)
		}
	}

	return allGadgets, nil
}
