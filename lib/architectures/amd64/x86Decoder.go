package amd64

import (
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/types"
	"golang.org/x/arch/x86/x86asm"
)

func InstructionDecoder(opcodes []byte) (*types.Instruction, error) {
	inst, err := x86asm.Decode(opcodes, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to decode instruction.")
	}
	return &types.Instruction{
		Octets: opcodes[0:inst.Len],
		DisAsm: inst.String(),
	}, nil
}

func GadgetDecoder(opcodes []byte) (types.Gadget, error) {
	gadget := types.Gadget{}

	for len(opcodes) > 0 {
		instr, err := InstructionDecoder(opcodes)
		if err != nil {
			return nil, errors.Wrapf(err, "Error decoding underlying instruction.")
		}
		gadget = append(gadget, instr)
		opcodes = opcodes[len(instr.Octets):]
	}
	return gadget, nil
}
