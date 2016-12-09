package strings

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestIsAlphaNumericBackend(t *testing.T) { TestingT(t) }

type IsAlphaNumericBackendSuite struct {
}

var _ = Suite(&IsAlphaNumericBackendSuite{})

func (b *IsAlphaNumericBackendSuite) TestIsAlphaNumericPositive(c *C) {

	result := IsAlphaNumeric("HelloWorldWithSomeNumbers123222")
	c.Assert(result, Equals, true)
}

func (b *IsAlphaNumericBackendSuite) TestIsAlphaNumericNegative(c *C) {

	result := IsAlphaNumeric("Hello World. This is a negative test.")
	c.Assert(result, Equals, false)

	result = IsAlphaNumeric("HelloWorldWithSomeNumbers123222andspaces ")
	c.Assert(result, Equals, false)
}
