package gadgets

import (
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/types"
)

func Find(opcodes []byte, gadgetSpecs []*types.GadgetSpec, decodeGadget types.GadgetDecoderFunc, offset types.Addr, depth int) (types.GadgetInstances, error, []error) {
	gadInstances := []*types.GadgetInstance{}
	if depth <= 2 {
		depth = 2
	}

	softerrs := []error{}

	for _, gadSpec := range gadgetSpecs {
		for match, err := gadSpec.Opcode.FindBytesMatchStartingAt(opcodes, 0); match != nil; match, err = gadSpec.Opcode.FindNextMatch(match) {
			if err != nil {
				return nil, errors.Wrapf(err, "Error attempting to find a match for gadget opcode: %v", gadSpec.Opcode), softerrs
			}

			for i := 0; i < depth; i++ {
				if (offset+types.Addr(match.Index)-(types.Addr(i)*gadSpec.Align))%gadSpec.Align == 0 {

					// Get the probable gadget at alignment
					start := types.Addr(match.Index) - (types.Addr(i) * gadSpec.Align)
					end := types.Addr(match.Index) + types.Addr(gadSpec.Size)
					if start >= end || end >= types.Addr(len(opcodes)) {
						continue
					}
					opcode := opcodes[start:end]

					// Disassemble it
					gad, err := decodeGadget(opcode)

					if err != nil {
						softerrs = append(softerrs, err)
						continue
					}

					// Ensure it's a real gadget with something in it.
					if gad.Len() == 0 {
						continue
					}

					// Ensure the byte sequence matches the regex we're parsing
					if match, err := gadSpec.Opcode.FindBytesMatchStartingAt(gad.Bytes(), 0); err != nil || match == nil {
						continue
					}

					vaddr := offset + types.Addr(match.Index) - (types.Addr(i) * gadSpec.Align)
					gadInstance := &types.GadgetInstance{
						Address: vaddr,
						Gadget:  gad,
					}
					gadInstances = append(gadInstances, gadInstance)
				}
			}
		}
	}
	return gadInstances, nil, softerrs
}
