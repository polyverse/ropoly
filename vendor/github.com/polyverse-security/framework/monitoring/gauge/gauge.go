package gauge

import (
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/monitoring/config"
	"github.com/polyverse-security/framework/reflection"
	"github.com/polyverse-security/statter"
	"strings"
	"time"
)

type Gauger struct {
	name       string
	logfields  map[string]interface{}
	logMetrics bool
}

func Gauge(name string, n int64) {
	g := NewGauge(name)
	g.Gauge(n)
}

func GaugeDelta(name string, n int64) {
	g := NewGauge(name)
	g.GaugeDelta(n)
}

func NewGaugeWithFields(name string, logfields map[string]interface{}) *Gauger {
	createTime := time.Now()
	counter := &Gauger{name: name, logMetrics: config.ShouldLogMetrics()}

	if counter.logMetrics {
		if _, ok := logfields["GaugeName"]; ok {
			log.Error("GaugeName is a special field added to the logs by the internals. You should not set it in log fields. It will be overridden this time.")
		}
		logfields["GaugeName"] = name
		logfields["CreateSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "gauger.NewGauge")
		})
		logfields["CreateTime"] = createTime
		counter.logfields = logfields
	}

	return counter
}

func NewGauge(name string) *Gauger {
	return NewGaugeWithFields(name, log.Fields{})
}

func (c *Gauger) Gauge(n int64) {
	if c.logMetrics {
		c.logfields["GaugeSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "gauger.Gauge")
		})
		c.logfields["GaugeTime"] = time.Now()
		c.logfields["Gauge"] = n
		delete(c.logfields, "GaugeDelta")

		log.WithFields(c.logfields).Info("Gauge")
	}

	statter.Gauge(config.GetStatterMetricPrefix()+c.name, n, 1)
	if config.ShouldStatToConsole() {
		config.GetConsoleStatter().Gauge(config.GetStatterMetricPrefix()+c.name, n, 1)
	}
}

func (c *Gauger) GaugeDelta(n int64) {
	if c.logMetrics {
		c.logfields["GaugeSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "gauger.GaugeDelta")
		})
		c.logfields["GaugeTime"] = time.Now()
		c.logfields["GaugeDelta"] = n
		delete(c.logfields, "Gauge")

		log.WithFields(c.logfields).Info("GaugeDelta")
	}

	statter.GaugeDelta(config.GetStatterMetricPrefix()+c.name, n, 1)
	if config.ShouldStatToConsole() {
		config.GetConsoleStatter().GaugeDelta(config.GetStatterMetricPrefix()+c.name, n, 1)
	}
}
