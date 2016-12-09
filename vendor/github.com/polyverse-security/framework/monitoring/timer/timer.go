package timer

import (
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/monitoring/config"
	"github.com/polyverse-security/framework/reflection"
	"github.com/polyverse-security/statter"
	"runtime"
	"strings"
	"time"
)

type Timer struct {
	name       string
	startTime  time.Time
	logfields  map[string]interface{}
	stopped    bool
	logMetrics bool
}

func TimeDuration(name string, duration time.Duration) {
	timeDurationInternal(name, duration, true)
}

func timeDurationInternal(name string, duration time.Duration, shouldLog bool) {

	statter.TimingDuration(config.GetStatterMetricPrefix()+name, duration, 1.0)
	if config.ShouldStatToConsole() {
		config.GetConsoleStatter().TimingDuration(config.GetStatterMetricPrefix()+name, duration, 1.0)
	}

	if shouldLog && config.ShouldLogMetrics() {
		logfields := log.Fields{}
		logfields["TimerName"] = name
		logfields["StartSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "timer.TimeDuration")
		})
		logfields["Duration"] = duration
		log.WithFields(logfields).Info("Timer")
	}
}

func NewTimerWithFields(name string, logfields map[string]interface{}) *Timer {
	startTime := time.Now()

	timer := &Timer{name: name, logMetrics: config.ShouldLogMetrics(), stopped: false, startTime: startTime}

	if timer.logMetrics {
		if _, ok := logfields["TimerName"]; ok {
			log.Error("TimerName is a special field added to the logs by the internals. You should not set it in log fields. It will be overridden this time.")
		}
		logfields["TimerName"] = name
		logfields["StartSite"] = reflection.GetCallstackSource(func(name string) bool {
			return strings.Contains(name, "timer.NewTimer")
		})
		logfields["StartTime"] = startTime

		runtime.SetFinalizer(timer, func(t *Timer) {
			//Call stop if not already called
			if !t.stopped {
				log.WithFields(logfields).Warning("Timer %d not stopped explicitly. Stopping it through a finalizer.")
				t.Stop()
			}
		})
		timer.logfields = logfields
	}

	return timer
}

func NewTimer(name string) *Timer {
	return NewTimerWithFields(name, log.Fields{})
}

func (t *Timer) Stop() {
	stopTime := time.Now()
	duration := stopTime.Sub(t.startTime)

	stopSite := reflection.GetCallstackSource(func(name string) bool {
		return strings.Contains(name, "timer.Stop")
	})

	if t.stopped {
		log.Warningf("The timer %s was already stopped from location %s. But Stop has been called again from location %s. This will take no effect.", t.name, t.logfields["StopSite"], stopSite)
		return
	}
	t.stopped = true

	if t.logMetrics {
		t.logfields["StopSite"] = stopSite
		t.logfields["StopTime"] = stopTime
		t.logfields["Duration"] = duration
		log.WithFields(t.logfields).Info("Timer")
	}

	timeDurationInternal(t.name, duration, false)

}
