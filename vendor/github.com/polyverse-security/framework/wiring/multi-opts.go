package wiring

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"strings"
)

/**
This structure is used for multiple option-maps when they are passed on the command-line. This is compatible
with the flags package so you can specify multiple options which can then be retrieved as a map.
*/
type MultipleOptions struct {
	OptionsMap map[string]string
}

func (l *MultipleOptions) String() string {
	if bytes, err := json.Marshal(*l); err != nil {
		return err.Error()
	} else {
		return string(bytes)
	}
}

func (l *MultipleOptions) Set(value string) error {
	if l.OptionsMap == nil {
		l.OptionsMap = make(map[string]string)
	}
	keyPair := strings.SplitN(value, "=", 2)
	if len(keyPair) != 2 {
		return fmt.Errorf("LoggerOption %v is not a key-value pair separated by an = sign.", value)
	}
	l.OptionsMap[keyPair[0]] = keyPair[1]
	return nil
}

/**
jsonVal can be an array of key=value pairs: ["key=value"]
jsonVal can be a struct of key:value pairs: {"key":"value"}
jsonVal can be a serialized MultipleOptions: {OptionsMap:{"key":"value"}}
*/
func (l *MultipleOptions) Parse(jsonVal string) {
	jsonVal = strings.TrimSpace(jsonVal)
	if len(jsonVal) == 0 {
		return
	}

	if jsonVal[0:1] == "[" {
		ltemp := []string{}
		if err := json.Unmarshal([]byte(jsonVal), &ltemp); err != nil {
			logrus.WithField("Error", err).Errorf("Unable to parse %s into a logger options map. Logger options will not apply correctly.", jsonVal)
		} else {
			for _, pair := range ltemp {
				l.Set(pair)
			}
		}
	} else if jsonVal[0:1] == "{" {
		ltemp := map[string]string{}
		if err := json.Unmarshal([]byte(jsonVal), &ltemp); err != nil {
			logrus.WithField("Error", err).Warning("Unable to parse %s into a logger options map. Logger options will not apply correctly.", jsonVal)
			if err := json.Unmarshal([]byte(jsonVal), l); err != nil {
				logrus.WithField("Error", err).Errorf("Unable to parse %s into a multiple options struct.", jsonVal)
			}
		} else {
			l.OptionsMap = ltemp
		}
	} else {
		logrus.WithField("JsonValue", jsonVal).Error("Unable to parse jsonVal into a multiple options structure.")
	}
}
