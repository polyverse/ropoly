package strings

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestIsAlphaNumericWithUnderscoreBackend(t *testing.T) { TestingT(t) }

type IsAlphaNumericWithUnderscoreBackendSuite struct {
}

var _ = Suite(&IsAlphaNumericWithUnderscoreBackendSuite{})

func (b *IsAlphaNumericWithUnderscoreBackendSuite) TestIsAlphaNumericWithUnderscorePositive(c *C) {

	result := IsAlphaNumericWithUnderscore("Hello_World_With_Some_Numbers_123222")
	c.Assert(result, Equals, true)
}

func (b *IsAlphaNumericWithUnderscoreBackendSuite) TestIsAlphaNumericWithUnderscoreNegative(c *C) {

	result := IsAlphaNumericWithUnderscore("Hello World. This is a negative test. __")
	c.Assert(result, Equals, false)

	result = IsAlphaNumericWithUnderscore("HelloWorldWithSomeNumbers123222andspaces ")
	c.Assert(result, Equals, false)
}
