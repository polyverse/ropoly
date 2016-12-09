package strings

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestIsNumericBackend(t *testing.T) { TestingT(t) }

type IsNumericBackendSuite struct {
}

var _ = Suite(&IsNumericBackendSuite{})

func (b *IsNumericBackendSuite) TestIsNumericPositive(c *C) {

	result := IsNumeric("1992")
	c.Assert(result, Equals, true)
}

func (b *IsNumericBackendSuite) TestIsNumericNegative(c *C) {
	result := IsNumeric("1992a")
	c.Assert(result, Equals, false)

	result = IsNumeric("3432 ")
	c.Assert(result, Equals, false)

	result = IsNumeric("37 33")
	c.Assert(result, Equals, false)
}
