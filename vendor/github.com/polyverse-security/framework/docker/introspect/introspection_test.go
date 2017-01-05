package introspect

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestIntrospection(t *testing.T) { TestingT(t) }

type IntrospectionBackendSuite struct {
}

var _ = Suite(&IntrospectionBackendSuite{})

func (b *IntrospectionBackendSuite) SetUpTest(c *C) {
}

func (b *IntrospectionBackendSuite) TestGetContainerIdFromCgroupContents(c *C) {
	//The extra arbitrary spaces before/after the lines are intentional, to ensure our function
	//handles cleaning up of whitespaces everywhere.
	contents := `
	14:name=systemd:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
     13:pids:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 12:hugetlb:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
   11:net_prio:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
   10:perf_event:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
   9:net_cls:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
  8:freezer:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 7:devices:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 6:memory:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 5:blkio:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 4:cpuacct:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 3:cpu:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 2:cpuset:/docker/c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903
 1:name=openrc:/docker
	`

	id, err := getContainerIdFromCgroupContents(contents)
	c.Assert(err, IsNil)
	c.Assert(id, Equals, "c6540bfff3ba9068e5e5a3626f79f66feb06df309c3fc94593c26e4310c81903")
}
