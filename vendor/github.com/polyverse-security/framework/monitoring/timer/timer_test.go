package timer

import (
	log "github.com/Sirupsen/logrus"
	. "gopkg.in/check.v1"
	"runtime"
	"testing"
)

/**********************************************************************************/

func TestBackend(t *testing.T) { TestingT(t) }

type BackendSuite struct {
}

var _ = Suite(&BackendSuite{})

func (s *BackendSuite) TestTimer(c *C) {
	t := NewTimer("Regular Timer")
	t.Stop()
}

func (s *BackendSuite) TestTimerGC(c *C) {
	NewTimer("Garbage Collected Timer")
	runtime.GC()
}

func (s *BackendSuite) TestTimerNameSet(c *C) {
	_ = NewTimerWithFields("NamedTimer", log.Fields{"TimerName": "NamedTimer"})
}

func (s *BackendSuite) TestTimerStoppedTwice(c *C) {
	t := NewTimerWithFields("NamedTimer", log.Fields{"TimerName": "NamedTimer"})
	t.Stop()
	t.Stop()
}
