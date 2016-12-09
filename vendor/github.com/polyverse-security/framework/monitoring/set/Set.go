package set

import (
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/monitoring/config"
	"github.com/polyverse-security/framework/reflection"
	"github.com/polyverse-security/statter"
	"strings"
	"time"
)

const (
	SetTypeInt = iota
	SetTypeString
)

type Set struct {
	name        string
	setType     int
	logfields   map[string]interface{}
	logMetrics  bool
	valueInt    int64
	valueString string
}

func (s *Set) Count() {
	name := config.GetStatterMetricPrefix() + s.name
	switch s.setType {
	case SetTypeInt:
		statter.SetInt(name, s.valueInt, 1.0)
	case SetTypeString:
		statter.Set(name, s.valueString, 1.0)
	default:
		log.Error("Set %v has an invalid type. It must be a string or an int.", s.name)
	}

	if s.logMetrics {
		s.logfields["CountSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "set.Count") ||
				strings.Contains(name, "set.Int") ||
				strings.Contains(name, "set.String")
		})
	}
}

func Int(name string, n int64) {
	NewInt(name, n).Count()
}

func String(name string, s string) {
	NewString(name, s).Count()
}

func NewInt(name string, valueInt int64) *Set {
	return NewIntWithFields(name, valueInt, log.Fields{})
}

func NewIntWithFields(name string, valueInt int64, logfields map[string]interface{}) *Set {
	set := newSetInternal(name, SetTypeInt, logfields)
	set.valueInt = valueInt
	return set
}

func NewString(name string, valueString string) *Set {
	return NewStringWithFields(name, valueString, log.Fields{})
}

func NewStringWithFields(name string, valueString string, logfields map[string]interface{}) *Set {
	set := newSetInternal(name, SetTypeString, logfields)
	set.valueString = valueString
	return set
}

func newSetInternal(name string, setType int, logfields log.Fields) *Set {

	createTime := time.Now()
	set := &Set{name: name, setType: setType, logMetrics: config.ShouldLogMetrics()}

	if set.logMetrics {
		if _, ok := logfields["SetName"]; ok {
			log.Error("SetName is a special field added to the logs by the internals. You should not set it in log fields. It will be overridden this time.")
		}
		logfields["SetName"] = name
		logfields["CreateSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "set.NewInt") ||
				strings.Contains(name, "set.NewString") ||
				strings.Contains(name, "set.Int") ||
				strings.Contains(name, "set.String")
		})
		logfields["CreateTime"] = createTime
		set.logfields = logfields
	}

	return set
}
