package lib

import (
	"context"
	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
	"os/exec"
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
	c.Assert(gadgets, NotNil)
	log.Infof("Gadgets in executable: %v", gadgets)
}

func (s *LibSuite) TestGadgetsFromPid(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Infof("Starting loop process...")
	process := exec.CommandContext(ctx, "../TestFiles/loop")
	err := process.Start()
	c.Assert(err, IsNil)

	loopPid := process.Process.Pid
	log.Infof("Loop process has pid %d", loopPid)

	gadgets, err, _ := GadgetsFromProcess(loopPid, 2)
	c.Assert(err, IsNil)
	c.Assert(gadgets, NotNil)

	log.Infof("Number of gadgets in Loop Process: %d (Expecting at least 1500)", len(gadgets))
	c.Assert(len(gadgets) > 15000, Equals, true)
}

func (s *LibSuite) TestLibrariesForPid(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Infof("Starting loop process...")
	process := exec.CommandContext(ctx, "../TestFiles/loop")
	err := process.Start()
	c.Assert(err, IsNil)

	loopPid := process.Process.Pid
	log.Infof("Loop process has pid %d", loopPid)

	libraries, err, _ := GetLibrariesForPid(loopPid, true)
	c.Assert(err, IsNil)
	c.Assert(libraries, NotNil)

	log.Infof("Number of libraries in Loop Process: %d", len(libraries))
	for _, lib := range libraries {
		polyversedEval := ""
		if !lib.PolyverseTained {
			polyversedEval = "NOT"
		}
		log.Infof("==> Library %s is %s Polyverse Tained", lib.Path, polyversedEval)
	}
}
