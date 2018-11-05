package types

import (
	"github.com/dlclark/regexp2"
)

type BinaryRegexp struct {
	internalRegexp *regexp2.Regexp
}

func (b *BinaryRegexp) FindStringMatchStartingAt(str string, startAt int) (*regexp2.Match, error) {
	return b.FindBytesMatchStartingAt([]byte(str), startAt)
}

func (b *BinaryRegexp) FindBytesMatchStartingAt(bytes []byte, startAt int) (*regexp2.Match, error) {
	runes := make([]rune, len(bytes))
	return b.internalRegexp.FindRunesMatchStartingAt(runes, startAt)
}

func MustCompile(expr string) *BinaryRegexp {
	return &BinaryRegexp{
		internalRegexp: regexp2.MustCompile(expr, regexp2.None),
	}
}

// Specifies the termination conditions for a gadget
// A gadget is typically <Some instruction set> + <some termination condition>
// A termination is a control-flow change
type GadgetEndSpec struct {
	opcode *BinaryRegexp
	size   int
	align  int
}
