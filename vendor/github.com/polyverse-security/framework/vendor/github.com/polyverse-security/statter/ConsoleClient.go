package statter

import (
	"fmt"
	"github.com/cactus/go-statsd-client/statsd"
	"time"
)

type ConsoleClient struct {
	// prefix for statsd name
	prefix      string
	samplerFunc statsd.SamplerFunc
}

// Close closes the connection and cleans up.
func (s *ConsoleClient) Close() error {
	return nil
}

// Increments a statsd count type.
// stat is a string name for the metric.
// value is the integer value
// rate is the sample rate (0.0 to 1.0)
func (s *ConsoleClient) Inc(stat string, value int64, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"Inc\"}}\n", s.prefix+stat, value)
	return nil
}

// Decrements a statsd count type.
// stat is a string name for the metric.
// value is the integer value.
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) Dec(stat string, value int64, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"Dec\"}}\n", stat, value)
	return nil
}

// Submits/Updates a statsd gauge type.
// stat is a string name for the metric.
// value is the integer value.
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) Gauge(stat string, value int64, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"Gauge\"}}\n", s.prefix+stat, value)
	return nil
}

// Submits a delta to a statsd gauge.
// stat is the string name for the metric.
// value is the (positive or negative) change.
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) GaugeDelta(stat string, value int64, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"GaugeDelta\"}}\n", stat, value)
	return nil
}

// Submits a statsd timing type.
// stat is a string name for the metric.
// delta is the time duration value in milliseconds
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) Timing(stat string, delta int64, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"Timing\"}}\n", s.prefix+stat, delta)
	return nil
}

// Submits a statsd timing type.
// stat is a string name for the metric.
// delta is the timing value as time.Duration
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) TimingDuration(stat string, delta time.Duration, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %v, type: \"TimingDuration\"}}\n", s.prefix+stat, delta)
	return nil
}

// Submits a stats set type.
// stat is a string name for the metric.
// value is the string value
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) Set(stat string, value string, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"Set\"}}\n", s.prefix+stat, value)
	return nil
}

// Submits a number as a stats set type.
// convenience method for Set with number.
// stat is a string name for the metric.
// value is the integer value
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) SetInt(stat string, value int64, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"SetInt\"}}\n", s.prefix+stat, value)
	return nil
}

// Raw formats the statsd event data, handles sampling, prepares it,
// and sends it to the server.
// stat is the string name for the metric.
// value is the preformatted "raw" value string.
// rate is the sample rate (0.0 to 1.0).
func (s *ConsoleClient) Raw(stat string, value string, rate float32) error {
	fmt.Printf("{stat: {name: \"%s\", value: %d, type: \"Raw\"}}\n", s.prefix+stat, value)
	return nil
}

// Sets/Updates the statsd client prefix
func (s *ConsoleClient) SetPrefix(prefix string) {
	s.prefix = prefix
}

func (s *ConsoleClient) SetSamplerFunc(samplerFunc statsd.SamplerFunc) {
	s.samplerFunc = samplerFunc
}

func (s *ConsoleClient) NewSubStatter(subPrefix string) statsd.SubStatter {
	subConsoleClient := &ConsoleClient{}
	subConsoleClient.SetPrefix(s.prefix + "." + subPrefix)
	return subConsoleClient
}

// Returns a pointer to a new NoopClient, and an error (always nil, just
// supplied to support api convention).
// Use variadic arguments to support identical format as NewClient, or a more
// conventional no argument form.
func NewConsoleClient(a ...interface{}) (statsd.Statter, error) {
	consoleClient := &ConsoleClient{}
	return consoleClient, nil
}

// Compatibility alias
var NewConsole = NewConsoleClient
