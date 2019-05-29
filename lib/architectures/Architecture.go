package architectures

import (
	"debug/elf"
	"debug/pe"
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	"github.com/polyverse/ropoly/lib/architectures/arm"
	"github.com/polyverse/ropoly/lib/types"
)

type Architecture int

const (
	X86 Architecture = 1
	ARM Architecture = 2
)

var ArchitecturesByName = map[string]Architecture {
	"x86": X86,
	"arm": ARM,
}

var ArchitecturesByPeMachine = map[uint16]Architecture {
	pe.IMAGE_FILE_MACHINE_AMD64: X86,
	pe.IMAGE_FILE_MACHINE_ARM: ARM,
	pe.IMAGE_FILE_MACHINE_I386: X86,
}

var ArchitecturesByElfMachine = map[elf.Machine]Architecture {
	elf.EM_X86_64: X86,
	elf.EM_ARM: ARM,
}

var GadgetDecoderFuncs = map[Architecture]types.GadgetDecoderFunc {
	X86: amd64.GadgetDecoder,
	ARM: arm.GadgetDecoder,
}

type GadgetSpecList []*types.GadgetSpec

var GadgetSpecLists = map[Architecture]GadgetSpecList {
	X86: amd64.GadgetSpecs,
	ARM: arm.GadgetSpecs,
}