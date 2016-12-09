package systemstats

import (
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/monitoring/config"
	"github.com/polyverse-security/framework/monitoring/gauge"
	"os"
	"runtime"
	"time"
)

func StatOnInterval(interval int) {
	go func() {
		for {
			gauge.Gauge("system.numGoRoutines", int64(runtime.NumGoroutine()))

			// General statistics.
			mem := &runtime.MemStats{}
			runtime.ReadMemStats(mem)
			gauge.Gauge("system.memStats.alloc", int64(mem.Alloc))           // bytes allocated and not yet freed
			gauge.Gauge("system.memStats.totalAlloc", int64(mem.TotalAlloc)) // bytes allocated (even if freed)
			gauge.Gauge("system.memStats.sys", int64(mem.Sys))               // bytes obtained from system (sum of XxxSys below)
			gauge.Gauge("system.memStats.lookups", int64(mem.Lookups))       // number of pointer lookups
			gauge.Gauge("system.memStats.mallocs", int64(mem.Mallocs))       // number of mallocs
			gauge.Gauge("system.memStats.frees", int64(mem.Frees))           // number of frees

			// Main allocation heap statistics.
			gauge.Gauge("system.memStats.heapAlloc", int64(mem.HeapAlloc))       // bytes allocated and not yet freed (same as Alloc above)
			gauge.Gauge("system.memStats.heapSys", int64(mem.HeapSys))           // bytes obtained from system
			gauge.Gauge("system.memStats.heapIdle", int64(mem.HeapIdle))         // bytes in idle spans
			gauge.Gauge("system.memStats.heapInuse", int64(mem.HeapInuse))       // bytes in non-idle span
			gauge.Gauge("system.memStats.heapReleased", int64(mem.HeapReleased)) // bytes released to the OS
			gauge.Gauge("system.memStats.heapObjects", int64(mem.HeapObjects))   // total number of allocated objects

			// Garbage collector statistics.
			gauge.Gauge("system.memStats.nextGC", int64(mem.NextGC)) // next collection will happen when HeapAlloc ≥ this amount
			gauge.Gauge("system.memStats.lastGC", int64(mem.LastGC)) // end time of last collection (nanoseconds since 1970)
			gauge.Gauge("system.memStats.pauseTotalNs", int64(mem.PauseTotalNs))
			gauge.Gauge("system.memStats.numGC", int64(mem.NumGC))

			log.WithFields(log.Fields{"interval": interval, "prefix": config.GetStatterMetricPrefix()}).Debugf("Completed StatOnInterval.")

			time.Sleep(time.Duration(interval) * time.Second)
		}
	}()
}

func RuntimeInfo() map[string]interface{} {
	info := make(map[string]interface{})
	info["version"] = runtime.Version()
	info["numCPU"] = runtime.NumCPU()
	info["GOROOT"] = runtime.GOROOT()
	info["binaryName"] = os.Args[0]
	return info
}
