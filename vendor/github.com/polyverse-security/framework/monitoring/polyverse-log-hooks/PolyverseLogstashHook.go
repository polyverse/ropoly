package polyverseloghooks

import (
	"github.com/Sirupsen/logrus"
	"github.com/polyverse-security/logrus-logstash-hook"
)

// EnableLogstash enables the logstash forwarder hook.
func EnableLogstash(server, serviceName string) error {
	hook, err := logrus_logstash.NewHook("udp", server, serviceName)
	if err != nil {
		return err
	}
	logrus.AddHook(hook)
	return nil
}
