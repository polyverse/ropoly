package wiring

import (
	. "gopkg.in/check.v1"
	"testing"
)

func TestMultipleOptions(t *testing.T) { TestingT(t) }

type MultipleOptionsBackendSuite struct {
}

var _ = Suite(&MultipleOptionsBackendSuite{})

func (b *MultipleOptionsBackendSuite) TestMultipleOptionsArray(c *C) {
	mo := MultipleOptions{}
	mo.Parse(`["key1=value1", "key2=value2"]`)
	c.Assert(mo.OptionsMap["key1"], Equals, "value1")
	c.Assert(mo.OptionsMap["key2"], Equals, "value2")
}

func (b *MultipleOptionsBackendSuite) TestMultipleOptionsStruct(c *C) {
	mo := MultipleOptions{}
	mo.Parse(`{"key1":"value1", "key2":"value2"}`)
	c.Assert(mo.OptionsMap["key1"], Equals, "value1")
	c.Assert(mo.OptionsMap["key2"], Equals, "value2")
}

func (b *MultipleOptionsBackendSuite) TestMultipleOptionsSerialized(c *C) {
	mo := MultipleOptions{}
	mo.Parse("{\"OptionsMap\":{\"key1\":\"value1\",\"key2\":\"value2\"}}")
	c.Assert(mo.OptionsMap["key1"], Equals, "value1")
	c.Assert(mo.OptionsMap["key2"], Equals, "value2")
}

func (b *MultipleOptionsBackendSuite) TestMultipleOptionsSerialize(c *C) {
	mo := MultipleOptions{
		OptionsMap: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}
	c.Assert(mo.String(), Equals, "{\"OptionsMap\":{\"key1\":\"value1\",\"key2\":\"value2\"}}")
}
