package types

import (
	"github.com/polyverse/binexp"
)

type BinaryRegexp struct {
	internalRegexp *binexp.Regexp
}

func (b *BinaryRegexp) FindBytesMatchStartingAt(bytes []byte, startAt int) (*binexp.Match, error) {
	return b.internalRegexp.FindBytesMatchStartingAt(bytes, startAt)
}

func (b *BinaryRegexp) FindNextMatch(m *binexp.Match) (*binexp.Match, error) {
	return b.internalRegexp.FindNextMatch(m)
}

func (b *BinaryRegexp) String() string {
	return b.internalRegexp.String()
}

func MustCompile(expr string) *BinaryRegexp {
	return &BinaryRegexp{
		internalRegexp: binexp.MustCompile(expr, binexp.ByteRunes),
	}
}

// Specifies the termination conditions for a gadget
// A gadget is typically <Some instruction set> + <some termination condition>
// A termination is a control-flow change
type GadgetSpec struct {
	Opcode *BinaryRegexp
	Size   int
	Align  Addr
}
