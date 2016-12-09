package strings

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestIsAlphabeticBackend(t *testing.T) { TestingT(t) }

type IsAlphabeticBackendSuite struct {
}

var _ = Suite(&IsAlphabeticBackendSuite{})

func (b *IsAlphabeticBackendSuite) TestIsAlphabeticPositive(c *C) {

	result := IsAlphabetic("HelloWorldThisisapositivetest")
	c.Assert(result, Equals, true)
}

func (b *IsAlphabeticBackendSuite) TestIsAlphabeticNegative(c *C) {
	result := IsAlphabetic("HelloWorld Thisisapositivetest")
	c.Assert(result, Equals, false)

	result = IsAlphabetic("HelloWorldThisisapositivetest0")
	c.Assert(result, Equals, false)

	result = IsAlphabetic("HelloWorldThisisapositivetest*")
	c.Assert(result, Equals, false)
}
