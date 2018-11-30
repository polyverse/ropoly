package lib

import (
	"debug/elf"
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	gadgets2 "github.com/polyverse/ropoly/lib/gadgets"
	"github.com/polyverse/ropoly/lib/types"
)

func GadgetsFromExecutable(path string, maxLength int) ([]*types.GadgetInstance, error, []error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "Error opening ELF file %s", path), nil
	}
	defer file.Close()

	allGadgets := []*types.GadgetInstance{}

	softerrs := []error{}
	for _, section := range file.Sections {
		if section.Type == elf.SHT_PROGBITS {
			progData, err := section.Data()
			if err != nil {
				return nil, errors.Wrapf(err, "Unable to read data from section in ELF file %s", file), nil
			}
			gadgetinstances, harderr, segment_softerrs := gadgets2.Find(progData, amd64.GadgetSpecs, amd64.GadgetDecoder, 0, 2)
			softerrs = append(softerrs, segment_softerrs...)
			if harderr != nil {
				return nil, errors.Wrapf(err, "Unable to find gadgets from Program segment in the ELF file."), softerrs
			}
			allGadgets = append(allGadgets, gadgetinstances...)
		}
	}

	return allGadgets, nil, softerrs
}
