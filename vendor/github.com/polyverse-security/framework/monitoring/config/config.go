package config

import (
	"github.com/cactus/go-statsd-client/statsd"
	"github.com/polyverse-security/framework/wiring"
	"github.com/polyverse-security/statter"
	"os"
)

var (
	logMetrics            bool
	logSourceLine         bool
	logCallstack          bool
	statToConsole         bool
	statterClusterNameSet bool
	statterClusterName    string
	statterContainerName  string
	consoleStatter        statsd.Statter
)

func init() {
	if cs, err := statter.NewConsole(); err != nil {
		consoleStatter, _ = statsd.NewNoop()
	} else {
		consoleStatter = cs
	}

	if name, err := os.Hostname(); err != nil {
		statterContainerName = "unnamed_container"
	} else {
		statterContainerName = name
	}
	statToConsole = false
	logSourceLine = false
	logMetrics = false
}

func getStatterClusterName() string {
	if !statterClusterNameSet {
		//Allow cluster name to be pulled from any etcd startup keys when possible.
		statterClusterName = wiring.StatterClusterPrefix.StringValueWithFallback()
		statterClusterNameSet = true
	}
	return statterClusterName
}

// Should metrics also be sent to the logger?
func EnableMetricsLogging(b bool) {
	logMetrics = b
}

func ShouldLogMetrics() bool {
	return logMetrics
}

// Should the lines and positions of source code be logged?
// It uses reflection and is a potentially expensive operation.
func EnableSourceCodeLineLogging(b bool) {
	logSourceLine = b
}

func ShouldLogSourceLine() bool {
	return logSourceLine
}

// Should the lines and positions of source code be logged?
// It uses reflection and is a potentially expensive operation.
func EnableCallstackLogging(b bool) {
	logCallstack = b
}

func ShouldLogCallstack() bool {
	return logCallstack
}

// Should the lines and positions of source code be logged?
// It uses reflection and is a potentially expensive operation.
func EnableStatToConsole(b bool) {
	statToConsole = b
}

func ShouldStatToConsole() bool {
	return statToConsole
}

func GetConsoleStatter() statsd.Statter {
	return consoleStatter
}

// Should the lines and positions of source code be logged?
// It uses reflection and is a potentially expensive operation.
func SetStatterClusterName(cluster string) {
	statterClusterName = cluster
}

func SetStatterContainerName(container string) {
	statterContainerName = container
	statterClusterNameSet = true
}

func GetStatterMetricPrefix() string {
	return "polyverse." + getStatterClusterName() + "." + statterContainerName + "."
}
