package lib

import (
	"debug/elf"
	"debug/pe"
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	"github.com/polyverse/ropoly/lib/gadgets"
	"github.com/polyverse/ropoly/lib/types"
	"sort"
)

func GadgetsFromFile(path string, maxLength int) (types.GadgetInstances, error, []error) {
	b, err := openBinary(path)
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
		gadgetinstances, harderr, segment_softerrs := gadgets.Find(progData, amd64.GadgetSpecs, amd64.GadgetDecoder, addr, maxLength)
		softerrs = append(softerrs, segment_softerrs...)
		if harderr != nil {
			return nil, errors.Wrapf(err, "Unable to find gadgets from Program segment in the ELF file."), softerrs
		}
		allGadgets = append(allGadgets, gadgetinstances...)
		sectionExists, addr, progData, err = b.nextSectionData()
	}

	return allGadgets, nil, softerrs
}

type binary interface {
	close() error
	nextSectionData() (bool, types.Addr, []byte, error)
}

func openBinary(path string) (binary, error) {
	elfFile, err := elf.Open(path)
	if err == nil {
		ret := elfBinary {
			binary: elfFile,
			sectionIndex: new(int),
		}
		sort.Sort(elfSections(ret.binary.Sections))
		return ret, nil
	}

	peFile, err := pe.Open(path)
	if err == nil {
		ret := peBinary {
			binary: peFile,
			sectionIndex: new(int),
		}
		sort.Sort(peSections(ret.binary.Sections))
		return ret, nil
	}

	return nil, errors.Wrapf(err, "Out of binary types for %s", path)
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