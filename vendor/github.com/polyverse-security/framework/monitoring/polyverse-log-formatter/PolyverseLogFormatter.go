//
// PolyverseFormatter is JSON-format optimized for Graylog. By using the Graylog-native fields "message", "timestamp" and "level",
// you can create a JSON input extractor for the field "message" that will re-write these default fields and add any additional fields
// that have been added with .WithFields() at the root-level of Graylog.
//

package polyverse_log_formatter

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"time"
)

func NewFormatter() log.Formatter {
	return &PolyverseFormatter{TimestampFormat: time.RFC3339Nano}
}

type PolyverseFormatter struct {
	TimestampFormat string
}

// Graylog uses an integer based on syslog semantics for the Level and actually fails to process the event with an error if it receives a string.
// An example of the error message:
//   [234]: index [graylog_0], type [message], id [ca27dc92-86c8-11e6-a299-0242ac110005], message [MapperParsingException[failed to parse [level]]; nested: NumberFormatException[For input string: "info"];]
// syslog event levels:
//   0 - Emergency: system is unusable
//   1 - Alert: action must be taken immediately
//   2 - Critical: critical conditions
//   3 - Error: error conditions
//   4 - Warning: warning conditions
//   5 - Notice: normal but significant condition
//   6 - Informational: informational messages
//   7 - Debug: debug-level messages

func syslogLevel(level log.Level) int {
	switch level {
	case log.PanicLevel:
		return 0 // Emergency: system is unusable
	case log.FatalLevel:
		return 2 // Critical
	case log.ErrorLevel:
		return 3 // Error
	case log.WarnLevel:
		return 4 // Warning
	case log.InfoLevel:
		return 6 // Informational
	case log.DebugLevel:
		return 7 // Debug
	default:
		return 5 // Notice
	}
}

func (f *PolyverseFormatter) Format(entry *log.Entry) ([]byte, error) {
	data := make(log.Fields, len(entry.Data)+3)
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			// Otherwise errors are ignored by `encoding/json`
			// https://github.com/Sirupsen/logrus/issues/137
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	timestampFormat := f.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = log.DefaultTimestampFormat
	}

	data["timestamp"] = entry.Time.Format(timestampFormat)
	data["message"] = entry.Message
	data["level"] = syslogLevel(entry.Level)

	serialized, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}
	return append(serialized, '\n'), nil
}
