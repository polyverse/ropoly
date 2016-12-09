package strings

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestContainsOnlyBackend(t *testing.T) { TestingT(t) }

type ContainsOnlyBackendSuite struct {
}

var _ = Suite(&ContainsOnlyBackendSuite{})

func (b *ContainsOnlyBackendSuite) TestContainsOnlyPositive(c *C) {

	result := ContainsOnly("Hello World. This is a positive test.", "HeloWrd. Thisaptve")
	c.Assert(result, Equals, true)

	result = ContainsOnly("Hello World. This is a positive test.", "HeloWrd. Thisaptve. Extra chars!")
	c.Assert(result, Equals, true)
}

func (b *ContainsOnlyBackendSuite) TestContainsOnlyNegative(c *C) {

	result := ContainsOnly("Hello World. This is a positive test.", "HeloWrd.Thisaptve")
	c.Assert(result, Equals, false)

	result = ContainsOnly("Hello World. This is a positive test.", "HeloWrd.Thisaptve-OtherChars")
	c.Assert(result, Equals, false)
}
