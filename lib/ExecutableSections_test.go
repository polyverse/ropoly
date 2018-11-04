package lib

import (
	. "gopkg.in/check.v1"
	"testing"
)

/**********************************************************************************/

func TestBackend(t *testing.T) {
	TestingT(t)
}

type LibSuite struct {
}

var _ = Suite(&LibSuite{})

func (b *LibSuite) SetUpSuite(c *C) {
}
func (b *LibSuite) TearDownSuite(c *C) {
}

/**********************************************************************************/

func (s *LibSuite) TestGadgetsFromExecutable(c *C) {
	gadgets, err := GadgetsFromExecutable("../TestFiles/loop", 2)
	c.Assert(err, IsNil)
	c.Assert(gadgets, HasLen, 20)
}


