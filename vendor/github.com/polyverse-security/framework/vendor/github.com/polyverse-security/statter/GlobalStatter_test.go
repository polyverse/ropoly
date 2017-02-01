package statter

import (
	. "gopkg.in/check.v1"
	"testing"
	"time"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type GlobalStatterTestSuite struct{}

var _ = Suite(&GlobalStatterTestSuite{})

type dummyStatter struct {
	Name string
	Func string
}

func (d *dummyStatter) Inc(name string, _ int64, _ float32) error {
	d.Name = name
	d.Func = "Inc"
	return nil
}

func (d *dummyStatter) Dec(name string, _ int64, _ float32) error {
	d.Name = name
	d.Func = "Dec"
	return nil
}

func (d *dummyStatter) Gauge(name string, _ int64, _ float32) error {
	d.Name = name
	d.Func = "Gauge"
	return nil
}

func (d *dummyStatter) GaugeDelta(name string, _ int64, _ float32) error {
	d.Name = name
	d.Func = "GaugeDelta"
	return nil
}

func (d *dummyStatter) Timing(name string, _ int64, _ float32) error {
	d.Name = name
	d.Func = "Timing"
	return nil
}

func (d *dummyStatter) TimingDuration(name string, _ time.Duration, _ float32) error {
	d.Name = name
	d.Func = "TimingDuration"
	return nil
}

func (d *dummyStatter) Set(name string, _ string, _ float32) error {
	d.Name = name
	d.Func = "Set"
	return nil
}

func (d *dummyStatter) SetInt(name string, _ int64, _ float32) error {
	d.Name = name
	d.Func = "SetInt"
	return nil
}

func (d *dummyStatter) Raw(name string, _ string, _ float32) error {
	d.Name = name
	d.Func = "Raw"
	return nil
}

func (d *dummyStatter) SetPrefix(_ string) {

}
func (d *dummyStatter) Close() error {
	return nil
}

func (s *GlobalStatterTestSuite) TestAllGlobals(c *C) {
	d := dummyStatter{}

	SetStatter(&d)

	Inc("Inc", 1, 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "Inc")

	Dec("Dec", 1, 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "Dec")

	Gauge("Gauge", 1, 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "Gauge")

	GaugeDelta("GaugeDelta", 1, 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "GaugeDelta")

	Timing("Timing", 1, 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "Timing")

	TimingDuration("TimingDuration", 1, 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "TimingDuration")

	Set("Set", "1", 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "Set")

	SetInt("SetInt", 1, 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "SetInt")

	Raw("Raw", "1", 1)
	c.Assert(d.Func, Equals, d.Name)
	c.Assert(d.Name, Equals, "Raw")
}

func (s *GlobalStatterTestSuite) TestNilDoesntCrash(c *C) {
	SetStatter(nil)
	err := Inc("test", 1, 1)
	c.Assert(err, NotNil)
}
