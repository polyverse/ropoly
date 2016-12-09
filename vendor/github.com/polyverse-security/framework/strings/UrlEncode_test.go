package strings

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestUrlEncodeBackend(t *testing.T) { TestingT(t) }

type UrlEncodeBackendSuite struct {
}

var _ = Suite(&UrlEncodeBackendSuite{})

func (b *UrlEncodeBackendSuite) TestUrlEncode(c *C) {

	result := UrlEncode("a b c")
	c.Assert(result, Equals, "a%20b%20c")
}
