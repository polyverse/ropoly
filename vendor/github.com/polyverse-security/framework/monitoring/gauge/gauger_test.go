package gauge

import (
	. "gopkg.in/check.v1"
	"testing"
)

/**********************************************************************************/

func TestBackend(t *testing.T) { TestingT(t) }

type BackendSuite struct {
}

var _ = Suite(&BackendSuite{})

func (s *BackendSuite) TestGauge(c *C) {
	gauge := NewGauge("RegularGauge")
	gauge.Gauge(10)
	gauge.GaugeDelta(2)
}

func (s *BackendSuite) TestGaugeFlat(c *C) {
	Gauge("FlatGauge", 5)
}
