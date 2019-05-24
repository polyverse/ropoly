package arm

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/types"
	"golang.org/x/arch/arm/armasm"
)

func InstructionDecoder(opcodes []byte) (instruction *types.Instruction, err error) {
	var inst armasm.Inst

	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("Unable to decode instruction due to disassembler panic: %v", x)
		}
	}()

	inst, err = armasm.Decode(opcodes, armasm.ModeARM)
	if err != nil {
		err = errors.Wrapf(err, "Unable to decode instruction.")
		return
	}

	instruction = &types.Instruction{
		Octets: opcodes[0:inst.Len],
		DisAsm: inst.String(),
	}
	return
}

func GadgetDecoder(opcodes []byte) (types.Gadget, error) {
	gadget := types.Gadget{}

	for len(opcodes) > 0 {
		instr, err := InstructionDecoder(opcodes)
		if err != nil {
			return nil, errors.Wrapf(err, "Error decoding underlying instruction.")
		}
		gadget = append(gadget, instr)
		gadlen := len(instr.Octets)
		if len(opcodes) <= gadlen {
			break
		}

		opcodes = opcodes[gadlen:]
	}
	return gadget, nil
}