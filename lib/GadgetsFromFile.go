package lib

import (
	"debug/elf"
	"debug/pe"
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/architectures"
	"github.com/polyverse/ropoly/lib/architectures/thumb"
	"github.com/polyverse/ropoly/lib/gadgets"
	"github.com/polyverse/ropoly/lib/types"
	"sort"
	"strconv"
)

func GadgetsFromFile(path string, maxLength int) (types.GadgetInstances, error, []error) {
	b, architecture, err := openBinary(path)
	if err != nil {
		return nil, err, nil
	}
	defer b.close()

	allGadgets := []*types.GadgetInstance{}

	softerrs := []error{}
	sectionExists, addr, progData, err := b.nextSectionData()
	for sectionExists {
		if err != nil {
			return nil, err, nil
		}
		gadgetinstances, harderr, segmentSofterrs := gadgets.Find(progData, architectures.GadgetSpecLists[architecture], architectures.GadgetDecoderFuncs[architecture], addr, maxLength)
		softerrs = append(softerrs, segmentSofterrs...)
		if harderr != nil {
			return nil, errors.Wrapf(err, "Unable to find gadgets from Program segment in the ELF file."), softerrs
		}
		allGadgets = append(allGadgets, gadgetinstances...)
		if architecture == architectures.ARM {
			gadgetinstances, harderr, segmentSofterrs := gadgets.Find(progData, thumb.GadgetSpecs, thumb.GadgetDecoder, addr, maxLength)
			softerrs = append(softerrs, segmentSofterrs...)
			if harderr != nil {
				return nil, errors.Wrapf(err, "Unable to find thumb gadgets"), softerrs
			}
			allGadgets = append(allGadgets, gadgetinstances...)
		}
		sectionExists, addr, progData, err = b.nextSectionData()
	}

	return allGadgets, nil, softerrs
}

type binary interface {
	close() error
	nextSectionData() (bool, types.Addr, []byte, error)
}

func openBinary(path string) (binary, architectures.Architecture, error) {
	elfFile, err := elf.Open(path)
	if err == nil {
		ret := elfBinary {
			binary: elfFile,
			sectionIndex: new(int),
		}
		machine := ret.binary.FileHeader.Machine
		architecture, ok := architectures.ArchitecturesByElfMachine[machine]
		if !ok {
			return nil, 0, errors.New("Cannot recognize ELF machine " + strconv.FormatUint(uint64(machine), 16))
		}
		sort.Sort(elfSections(ret.binary.Sections))
		return ret, architecture, nil
	}

	peFile, err := pe.Open(path)
	if err == nil {
		ret := peBinary {
			binary: peFile,
			sectionIndex: new(int),
		}
		machine := ret.binary.FileHeader.Machine
		architecture, ok := architectures.ArchitecturesByPeMachine[machine]
		if !ok {
			return nil, 0, errors.New("Cannot recognize PE machine " + strconv.FormatUint(uint64(machine), 16))
		}
		sort.Sort(peSections(ret.binary.Sections))
		return ret, architecture, nil
	}

	return nil, 0, errors.Wrapf(err, "Out of binary types for %s", path)
}

type elfBinary struct {
	binary *elf.File
	sectionIndex *int
}

func (b elfBinary) close() error {
	return b.binary.Close()
}

type elfSections []*elf.Section

func (s elfSections) Len() int {
	return len(s)
}

func (s elfSections) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s elfSections) Less(i, j int) bool {
	return s[i].Addr < s[j].Addr
}

func (b elfBinary) nextSectionData() (bool, types.Addr, []byte, error) {
	if *b.sectionIndex == len(b.binary.Sections) {
		return false, 0, nil, nil
	}

	section := b.binary.Sections[*b.sectionIndex]
	*b.sectionIndex++

	if section.Type == elf.SHT_PROGBITS {
		progData, err := section.Data()
		return true, types.Addr(section.Addr), progData, err
	} else {
		return b.nextSectionData()
	}
}

type peBinary struct {
	binary *pe.File
	sectionIndex *int
}

func (b peBinary) close() error {
	return b.binary.Close()
}

type peSections []*pe.Section

func (s peSections) Len() int {
	return len(s)
}

func (s peSections) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s peSections) Less(i, j int) bool {
	return s[i].Offset < s[j].Offset
}

const IMAGE_SCN_CNT_CODE uint32 = 0x00000020

func (b peBinary) nextSectionData() (bool, types.Addr, []byte, error) {
	if *b.sectionIndex == len(b.binary.Sections) {
		return false, 0, nil, nil
	}

	section := b.binary.Sections[*b.sectionIndex]
	*b.sectionIndex++

	if section.Characteristics & IMAGE_SCN_CNT_CODE != 0 {
		progData, err := section.Data()
		return true, types.Addr(section.Offset), progData, err
	} else {
		return b.nextSectionData()
	}
}