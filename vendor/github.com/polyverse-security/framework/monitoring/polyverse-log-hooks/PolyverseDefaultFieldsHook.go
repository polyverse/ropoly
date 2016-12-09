package polyverseloghooks

import (
	"github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/monitoring/config"
	"github.com/polyverse-security/framework/reflection"
	"strings"
)

type polyverseDefaultFieldsHook struct {
}

func NewHook() *polyverseDefaultFieldsHook {
	return &polyverseDefaultFieldsHook{}
}

func (hook *polyverseDefaultFieldsHook) Fire(entry *logrus.Entry) error {
	if config.ShouldLogSourceLine() {
		entry.Data["SourceLocation"] = reflection.GetCallstackSource(isLoggerFunc)
	}
	if config.ShouldLogCallstack() {
		entry.Data["Callstack"] = reflection.GetCallstackFormatted()
	}
	return nil
}

func isLoggerFunc(funcName string) bool {
	if strings.Contains(funcName, "logrus.") {
		return true
	}
	return false
}

// Operate on ALL levels
func (hook *polyverseDefaultFieldsHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.DebugLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}
