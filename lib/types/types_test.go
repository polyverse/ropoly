package types

import (
	"encoding/json"
	. "gopkg.in/check.v1"
	"testing"
)

/**********************************************************************************/

func TestTypes(t *testing.T) {
	TestingT(t)
}

type TypesSuite struct {
}

var _ = Suite(&TypesSuite{})

func (b *TypesSuite) SetUpSuite(c *C) {
}
func (b *TypesSuite) TearDownSuite(c *C) {
}

/**********************************************************************************/

func (s *TypesSuite) TestAddrSerializeDeserialize(c *C) {
	var a Addr = 10
	c.Assert(a.String(), Equals, "0x00000000000a")
	aj, err := a.MarshalJSON()
	c.Assert(err, IsNil)
	c.Assert(string(aj), Equals, "\"0x00000000000a\"")
	var b Addr
	err = b.UnmarshalJSON(aj)
	c.Assert(err, IsNil)

	c.Assert(a, Equals, b)
}


func (s *TypesSuite) TestAddrSerializeDeserializeJSON(c *C) {
	var a Addr = 10
	aj, err := a.MarshalJSON()

	var b Addr
	err = json.Unmarshal(aj, &b)
	c.Assert(err, IsNil)
	c.Assert(a, Equals, b)
}


func (s *TypesSuite) TestOctetSerializeDeserialize(c *C) {
	var a Octets = []byte{0x10, 0x05, 0xff, 0x12}
	c.Assert(a.String(), Equals, "0x10 0x05 0xff 0x12")
	aj, err := a.MarshalJSON()
	c.Assert(err, IsNil)
	c.Assert(string(aj), Equals, "\"0x10 0x05 0xff 0x12\"")
	var b Octets
	err = b.UnmarshalJSON(aj)
	c.Assert(err, IsNil)

	c.Assert(a.String(), Equals, b.String())
}


func (s *TypesSuite) TestOctetSerializeDeserializeJSON(c *C) {
	var a Octets = []byte{0x10, 0x05, 0xff, 0x12}
	aj, err := a.MarshalJSON()

	var b Octets
	err = json.Unmarshal(aj, &b)
	c.Assert(err, IsNil)
	c.Assert(a.String(), Equals, b.String())
}

/*

func (s *TypesSuite) TestRegexBinaryMatchBasic(c *C) {

	// Ensure this is a non-UTF-8 compliant string
	_, err := regexp.Compile("\x65\xff\x15")
	c.Assert(err, NotNil)

	spec := GadgetEndSpec{
		MustCompile("\x65\xff\x15"),
		2,
		1,
	}

	data := string([]byte{0x65, 0xff, 0x15, 0xef, 0x65, 0x15, 0xcd, 0x50, 0x65, 0xff, 0x15, 0x25})

	match, err := spec.opcode.FindStringMatchStartingAt(data, 0)
	c.Assert(err, IsNil)
	c.Assert(match.Index, Equals, 0)
	c.Assert(match.Length, Equals, 3)

	match, err = spec.opcode.FindStringMatchStartingAt(data, 1)
	c.Assert(err, IsNil)
	c.Assert(match.Index, Equals, 8)
	c.Assert(match.Length, Equals, 3)


	match, err = spec.opcode.FindStringMatchStartingAt(data, 8)
	c.Assert(err, IsNil)
	c.Assert(match.Index, Equals, 8)
	c.Assert(match.Length, Equals, 3)

	match, err = spec.opcode.FindStringMatchStartingAt(data, 9)
	c.Assert(err, IsNil)
	c.Assert(match, IsNil)
}

func (s *TypesSuite) TestRegexBinaryMatchComplex(c *C) {
	spec := GadgetEndSpec{
		MustCompile("\xca[\x00-\xff]{2}"),
		3,
		1,
	}

	runes := []rune{}
	rawbytes := []byte{0x65, 0xca, 0x05, 0xf4, 0x65, 0xca, 0xaf, 0xca, 0x65, 0xff, 0x15, 0x25}
	bytesStr := ""
	for _, b := range rawbytes {
		runes = append(runes, rune(b))
		bytesStr += fmt.Sprintf("%d ", b)
	}
	fmt.Printf("Bytes: %s\n", bytesStr)

	data := string(rawbytes)
	runesStr := ""
	for _, r := range runes {
		runesStr += fmt.Sprintf("%d ", r)
	}
	fmt.Printf("Runes: %s\n", runesStr)

	c.Assert(bytesStr, Equals, runesStr)

	match, err := spec.opcode.FindStringMatchStartingAt(data, 0)
	c.Assert(err, IsNil)
	fmt.Printf("Match: %v\n", match.Runes())
	c.Assert(match.Index, Equals, 1)
	c.Assert(match.Length, Equals, 3)

	match, err = spec.opcode.FindStringMatchStartingAt(data, 2)
	c.Assert(err, IsNil)
	fmt.Printf("Match: %v\n", match.Runes())
	c.Assert(match.Index, Equals, 3)
	c.Assert(match.Length, Equals, 3)


	match, err = spec.opcode.FindStringMatchStartingAt(data, 4)
	c.Assert(err, IsNil)
	fmt.Printf("Match: %v\n", match.Runes())
	c.Assert(match.Index, Equals, 6)
	c.Assert(match.Length, Equals, 3)

	match, err = spec.opcode.FindStringMatchStartingAt(data, 11)
	c.Assert(err, IsNil)
	c.Assert(match, IsNil)
}
*/