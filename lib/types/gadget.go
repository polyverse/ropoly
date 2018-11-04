package types

import (
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/polyverse/disasm"
)

type Gadget struct {
	Address          disasm.Ptr           `json:"address"`
	InstructionCount int                  `json:"instructionCount"`
	OctetCount       int                  `json:"octetCount"`
	Instructions     []disasm.Instruction `json:"instructions"`
}

func (g *Gadget) ToJson() (string, error) {
	marshaled, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return "", errors.Wrapf(err, "Unable to marshal gadget to JSON: %v", g.Instructions)
	}
	return string(marshaled), nil
}
