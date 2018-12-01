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
