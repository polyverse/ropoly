package architectures

import (
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

var GadgetDecoderFuncs = map[Architecture]types.GadgetDecoderFunc {
	X86: amd64.GadgetDecoder,
	ARM: arm.GadgetDecoder,
}

type GadgetSpecList []*types.GadgetSpec

var GadgetSpecLists = map[Architecture]GadgetSpecList {
	X86: amd64.GadgetSpecs,
	ARM: arm.GadgetSpecs,
}