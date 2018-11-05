package types

type DecoderFunc func([]byte) (*Instruction, error)
