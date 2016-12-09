package reflection

import (
	"fmt"
	. "gopkg.in/check.v1"
	"strings"
	"testing"
)

/**********************************************************************************/

func TestBackend(t *testing.T) { TestingT(t) }

type BackendSuite struct {
}

var _ = Suite(&BackendSuite{})

var source string = "fail"

func (s *BackendSuite) TestLogContainsSourceLocationFields(c *C) {
	//You should see "level2()" as the output because that's where the "callsite" function was called,
	//whose caller we are searching for.
	level1()
	fmt.Printf("Source: %s", source)
	c.Assert("github.com/polyverse-security/framework/reflection.level2(/Users/archis/Polyverse/src/github.com/polyverse-security/framework/reflection/get-callstack-source_test.go:34)", Equals, source)
}

func level1() {
	level2()
}

func level2() {
	callsite()
}

func callsite() {
	insidecallsite1()
}

func insidecallsite1() {
	insidecallsite2()
}

func insidecallsite2() {
	source = GetCallstackSource(isCallsite)
}

func isCallsite(funcname string) bool {
	return strings.Contains(funcname, "callsite")
}
