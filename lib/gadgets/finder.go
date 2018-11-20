package gadgets

import (
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/lib/types"
)

const (
	PREV_BYTES = 9 //# Number of bytes prior to the gadget to store.
)

func Find(opcodes []byte, gadgetSpecs []*types.GadgetSpec, decode types.DecoderFunc, offset int, depth int) ([]*types.GadgetInstance, error) {
	gadgets := []*types.GadgetInstance{}
	if depth <= 2 {
		depth = 2
	}

	for _, gad := range gadgetSpecs {
		for match, err := gad.Opcode.FindBytesMatchStartingAt(opcodes, 0); match != nil; match, err = gad.Opcode.FindNextMatch(match) {
			if err != nil {
				return nil, errors.Wrapf(err, "Error attempting to find a match for gadget opcode: %v", gad.Opcode)
			}

			for i := 0; i < depth; i++ {
				//(section["vaddr"]+ref-(i*gad[C_ALIGN])) % gad[C_ALIGN] == 0
				if (offset+match.Index-(i*gad.Align))%gad.Align == 0 {
					opcode := opcodes[match.Index-(i*gad.Align) : match.Index+gad.Size]
					instr, err := decode(opcode)
					if err != nil {
						log.De
					}
				}
			}
		}
	}
	/*
		let decodes = [];
		try {
		decodes = md.disasm(opcode, section["vaddr"]+ref);
		} catch (e) {
		if (typeof(errorTypes[e]) === 'undefined') {
		errorTypes[e] = 1;
		} else {
		errorTypes[e]++;
		}
		continue
		}
		let gadget = "";
		let lastdecode;
		for (let decodei in decodes) {
		const decode = decodes[decodei];
		gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ");
		lastdecode = decode;
		}
		if (!lastdecode || !opri.exec(encodeArray(lastdecode.bytes))) {
		continue;
		}
		if (gadget.length > 0) {
		gadget = gadget.slice(0,gadget.length-3);
		const off = offset;
		const vaddr = off+section["vaddr"]+ref-(i*gad[C_ALIGN]);
		const prevBytesAddr = Math.max(section["vaddr"], vaddr - PREV_BYTES);
		const prevBytes = section["opcodes"].slice(prevBytesAddr-section["vaddr"],vaddr-section["vaddr"]);
		const newGad = {
		"vaddr" :  vaddr,
		"gadget" : gadget,
		"decodes" : decodes,
		"bytes": section["opcodes"].slice(ref-(i*gad[C_ALIGN]),ref+gad[C_SIZE]),
		"prev": prevBytes
		};
		ret.push(newGad);
		}
		}
		}
		}
		}

		postMessage({status: "Following errors occurred when finding rop gadgets: " + JSON.stringify(errorTypes)});

		try {
		md.close();
		} catch (e) {
		postMessage({status: "Ignoring capstone close error: " + e});
		}
		}
	*/
	return gadgets, nil
}
