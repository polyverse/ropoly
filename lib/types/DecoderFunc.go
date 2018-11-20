package types

type InstructionDecoderFunc func([]byte) (*Instruction, error)
type GadgetDecoderFunc func([]byte) (*Gadget, error)
