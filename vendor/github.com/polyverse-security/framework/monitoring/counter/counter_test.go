package counter

import (
	. "gopkg.in/check.v1"
	"testing"
)

/**********************************************************************************/

func TestBackend(t *testing.T) { TestingT(t) }

type BackendSuite struct {
}

var _ = Suite(&BackendSuite{})

func (s *BackendSuite) TestCounter(c *C) {
	cntr := NewCounter("RegularCounter")
	cntr.CountN(10)
	cntr.CountOne()
}

func (s *BackendSuite) TestCounterFlat(c *C) {
	CountOne("CountOne")
}
