package diags

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/clientv3"
	"github.com/polyverse-security/framework/control-flow/canceller"
	"github.com/polyverse-security/framework/control-flow/events"
	"github.com/polyverse-security/framework/monitoring/config"
	"github.com/polyverse-security/framework/wiring"
	"os"
	"runtime/pprof"
	"strconv"
)

type (
	configurationChangeHandler func(confEvent *etcd.Event) error
)

var (
	HandleConfigurationChange configurationChangeHandler
)

func init() {
	HandleConfigurationChange = defaultConfigurationHandler
}

func defaultConfigurationHandler(confEvent *etcd.Event) error {
	return fmt.Errorf("Unsupported profiler config value: %v", string(confEvent.Kv.Value))
}

func ListenToConfigChanges(canceller *canceller.Canceller) {
	events.WatchEtcdKeyWithCancel(canceller, wiring.MonitoringRootKey.Name(), func(confEvent *etcd.Event) error {
		log.Infof("Polyverse config change : %+v", string(confEvent.Kv.Key))
		switch string(confEvent.Kv.Key) {
		case wiring.DebugLevel.Name():
			level, err := log.ParseLevel(string(confEvent.Kv.Value))
			if err != nil {
				log.Error(err)
			} else {
				log.Infof("Debug level changed to %v", level)
				log.SetLevel(level)
			}
		case wiring.LogSourceLine.Name():
			b, err := strconv.ParseBool(string(confEvent.Kv.Value))
			if err != nil {
				log.Error(err)
			} else {
				log.Infof("Setting Logging of Source line to: %v", b)
				config.EnableSourceCodeLineLogging(b)
			}
		case wiring.LogCallstack.Name():
			b, err := strconv.ParseBool(string(confEvent.Kv.Value))
			if err != nil {
				log.Error(err)
			} else {
				log.Infof("Setting Logging of Source line to: %v", b)
				config.EnableCallstackLogging(b)
			}
		case wiring.LogMetrics.Name():
			b, err := strconv.ParseBool(string(confEvent.Kv.Value))
			if err != nil {
				log.Error(err)
			} else {
				log.Infof("Setting Logging of Metrics to: %v", b)
				config.EnableMetricsLogging(b)
			}
		case wiring.StatsToConsole.Name():
			b, err := strconv.ParseBool(string(confEvent.Kv.Value))
			if err != nil {
				log.Error(err)
			} else {
				log.Infof("Setting printing Metrics to console: %v", b)
				config.EnableStatToConsole(b)
			}
		case wiring.StatterClusterPrefix.Name():
			cluster := string(confEvent.Kv.Value)
			log.Infof("Setting Statter Prefix to: %v", cluster)
			config.SetStatterClusterName(cluster)
		case wiring.Profiler.Name():
			switch string(confEvent.Kv.Value) {
			case "on":
				profileFile := wiring.ProfilerOutputFilename.StringValueWithFallback()

				// Cleanup - just in case on/off commands sequence out of order
				os.Remove(profileFile)
				// Start profiling
				log.Info("Start profiling....")
				f, err := os.Create(profileFile)
				if err != nil {
					log.Errorf("Can't create profile file: %v", err)
					return nil // Continue watching
				}
				pprof.StartCPUProfile(f)
				log.Infof("CPU Profiling active. Saving profile data to %s", profileFile)
			case "off":
				log.Info("Stop profiling....")
				pprof.StopCPUProfile()
				log.Info("Profiling turned off")
			case "heap":
				heapProfileFile := wiring.ProfilerHeapOutputFile.StringValueWithFallback()

				os.Remove(heapProfileFile)
				f, err := os.Create(heapProfileFile)
				if err != nil {
					log.Errorf("Can't create profile file: %v", err)
					return nil // Continue watching
				}
				pprof.Lookup("heap").WriteTo(f, 0)
				log.Infof("Saved heap profile file to %s", heapProfileFile)
			default:
				log.Errorf("Unsupported profiler config value: %v", string(confEvent.Kv.Value))
			}
		default:
			if err := HandleConfigurationChange(confEvent); err != nil {
				log.Error(err)
			}
			log.Errorf("Unsupported config key: %v", string(confEvent.Kv.Key))
		}
		return nil
	})
}
