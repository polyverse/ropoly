package counter

import (
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/monitoring/config"
	"github.com/polyverse-security/framework/reflection"
	"github.com/polyverse-security/statter"
	"strings"
	"time"
)

type Counter struct {
	name       string
	logfields  map[string]interface{}
	logMetrics bool
}

func CountOne(name string) {
	CountN(name, 1)
}

func CountN(name string, n int64) {
	c := NewCounter(name)
	c.CountN(n)
}

func NewCounterWithFields(name string, logfields map[string]interface{}) *Counter {
	createTime := time.Now()
	counter := &Counter{name: name, logMetrics: config.ShouldLogMetrics()}

	if counter.logMetrics {
		if _, ok := logfields["CounterName"]; ok {
			log.Error("CounterName is a special field added to the logs by the internals. You should not set it in log fields. It will be overridden this time.")
		}
		logfields["CounterName"] = name
		logfields["CreateSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "NewCounter")
		})
		logfields["CreateTime"] = createTime
		counter.logfields = logfields
	}

	return counter
}

func NewCounter(name string) *Counter {
	return NewCounterWithFields(name, log.Fields{})
}

func (c *Counter) CountOne() {
	c.CountN(1)
}

func (c *Counter) CountN(n int64) {
	if c.logMetrics {
		c.logfields["CountSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "counter.Count")
		})
		c.logfields["CountTime"] = time.Now()
		c.logfields["Count"] = n

		log.WithFields(c.logfields).Info("Counter")
	}

	statter.Inc(config.GetStatterMetricPrefix()+c.name, n, 1)
	if config.ShouldStatToConsole() {
		config.GetConsoleStatter().Inc(config.GetStatterMetricPrefix()+c.name, n, 1)
	}
}
