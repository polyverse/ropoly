package polyverseloghooks

import (
	log "github.com/Sirupsen/logrus"
	. "gopkg.in/check.v1"
	"testing"
)

/**********************************************************************************/

func TestBackend(t *testing.T) { TestingT(t) }

type BackendSuite struct {
}

var _ = Suite(&BackendSuite{})

func (s *BackendSuite) TestLogContainsSourceLocationFields(c *C) {
	log.AddHook(&polyverseDefaultFieldsHook{}) //Add the hook
	log.Debug("Debug")
	log.Infof("Infof")
	log.Warnln("Warnln")
}
