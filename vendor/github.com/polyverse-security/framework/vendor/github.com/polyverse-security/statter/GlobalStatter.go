package statter

import (
	"fmt"
	"github.com/cactus/go-statsd-client/statsd"
	"time"
)

var globalStatter statsd.Statter

// Init the global statter to a Noop statter
func init() {
	globalStatter, _ = statsd.NewNoop()
}

//The polyverse Statter-specific interface
func SetStatter(statter statsd.Statter) {
	globalStatter = statter
}

func GetStatter() statsd.Statter {
	return globalStatter
}

//The global statter exposed as a flat API
//These functions are kept in sync with statsd.Statter API
//with a few exceptions, viz. No Close() or SetPrefix()
//functions (because in a global statter, setting prefixes
// can cause problems.)
func Inc(name string, value int64, rate float32) error {
	if globalStatter != nil {
		return globalStatter.Inc(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func Dec(name string, value int64, rate float32) error {
	if globalStatter != nil {
		return globalStatter.Dec(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func Gauge(name string, value int64, rate float32) error {
	if globalStatter != nil {
		return globalStatter.Gauge(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func GaugeDelta(name string, value int64, rate float32) error {
	if globalStatter != nil {
		return globalStatter.GaugeDelta(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func Timing(name string, value int64, rate float32) error {
	if globalStatter != nil {
		return globalStatter.Timing(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func TimingDuration(name string, value time.Duration, rate float32) error {
	if globalStatter != nil {
		return globalStatter.TimingDuration(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func Set(name string, value string, rate float32) error {
	if globalStatter != nil {
		return globalStatter.Set(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func SetInt(name string, value int64, rate float32) error {
	if globalStatter != nil {
		return globalStatter.SetInt(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}

func Raw(name string, value string, rate float32) error {
	if globalStatter != nil {
		return globalStatter.Raw(name, value, rate)
	} else {
		return fmt.Errorf("Global Statter was found to be nil.")
	}
}
