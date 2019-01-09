package cmd

import (
	"github.com/docker/docker/pkg/ioutils"
	"github.com/polyverse/ropoly/lib"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	LogEnabled        bool
	PrometheusEnabled bool
	PrometheusAddress string

	ScanFiles bool
	ScanProcs bool

	FileScanRoot      string
	FileScanBlacklist []string

	scanLogger *log.Logger
)

func init() {
	rootCmd.AddCommand(daemonCmd)
	daemonCmd.Flags().BoolVarP(&LogEnabled, "log", "l", false, "When enabled, Log scanner results to console")

	daemonCmd.Flags().BoolVarP(&PrometheusEnabled, "prometheus", "p", true, "When enabled, expose scanner results over prometheus")
	daemonCmd.Flags().StringVar(&PrometheusAddress, "prometheus-address", ":8008", "When prometheus is enabled, the address at which to host the server")

	daemonCmd.Flags().BoolVar(&ScanFiles, "scan-files", true, "When enabled, Scans files on disk (that Ropoly has permissions to)")
	daemonCmd.Flags().StringVar(&FileScanRoot, "file-scan-root", "/", "When file scan is enabled, the root under which to scan files.")
	daemonCmd.Flags().StringSliceVar(&FileScanBlacklist, "file-scan-blacklist", []string{"/proc"}, "When file scan is enabled, the root under which to scan files.")

	daemonCmd.Flags().BoolVar(&LogEnabled, "scan-procs", true, "When enabled, Scans processes in memory (that Ropoly has permissions to)")
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run Ropoly as a background scanner daemon.",
	Long: `Run Ropoly as a background scanner daemon that will iterate over files and processes. 
Results can be logged or exposed over a prometheus endpoint.`,
	Run: func(cmd *cobra.Command, args []string) {
		if !LogEnabled && !PrometheusEnabled {
			log.Fatalf("Daemon mode requires that at least one form of scanner output be enabled: Logs or Prometheus metrics. You have disabled both.")
		}

		if !ScanFiles && !ScanProcs {
			log.Fatalf("Daemon mode requires that at least one target be scanned: Files or Processes. You have disabled both.")
		}

		if PrometheusEnabled {
			log.Infof("Starting Prometheus server at address %s...", PrometheusAddress)
			go func() {
				log.Fatal(http.ListenAndServe(PrometheusAddress, promhttp.Handler()))
			}()
		} else {
			log.Infof("No Prometueus endpoint hosted for scan results")
		}

		if LogEnabled {
			log.Infof("Scan results will be sent to Logger...")
			scanLogger = log.New()
			scanLogger.Formatter = &log.JSONFormatter{}
		} else {
			log.Infof("Scan results will not be logged.")
			scanLogger = log.New()
			scanLogger.SetOutput(&ioutils.NopWriter{})
		}

		wg := &sync.WaitGroup{}

		if ScanFiles {
			log.Infof("Starting Ropoly file scanner in an infinite loop....")
			wg.Add(1)
			go scanFiles(wg)
		}

		if ScanProcs {
			log.Infof("Starting Ropoly process scanner in an infinite loop....")
			wg.Add(1)
			go scanProcs(wg)
		}

		wg.Wait()
	},
}

func scanFiles(wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		rootScanStartTime := time.Now()

		filepath.Walk(FileScanRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				scanLogger.WithError(err).Errorf("Error walking path %s", path)
				return nil
			}

			if isBlackListed(path) {
				scanLogger.Infof("Skipping path %s because it is blacklisted under %v", path, FileScanBlacklist)
				return filepath.SkipDir
			}

			if !info.IsDir() {
				fileScanStartTime := time.Now()
				hasPvSignature, err := lib.HasPolyverseTaint(path)
				fileScanEndTime := time.Now()
				if err != nil {
					scanLogger.WithError(err).Errorf("Error when attempting to check file %s for PV signature.", info.Name())
				}
				scanLogger.
					WithField("Info", info).
					WithField("Path", path).
					WithField("StartTime", fileScanStartTime).
					WithField("EndTime", fileScanEndTime).
					WithField("Duration", fileScanEndTime.Sub(fileScanStartTime)).
					WithField("Path", path).
					WithField("HasPVSignature", hasPvSignature).Info("FileScan")
			}
			return err
		})

		rootScanEndTime := time.Now()

		scanLogger.
			WithField("StartTime", rootScanStartTime).
			WithField("EndTime", rootScanEndTime).
			WithField("Duration", rootScanEndTime.Sub(rootScanStartTime)).
			Info("FileSystemScan")
	}
}

func scanProcs(wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		processListScanStartTime := time.Now()

		processes, harderror, softerrors := lib.GetAllPids()
		if harderror != nil {
			scanLogger.WithError(harderror).Errorf("Unable to list Process IDs on this system.")
		} else {
			for _, softerr := range softerrors {
				scanLogger.WithError(softerr).Warning("[Non-Critical] Error when listing Process IDs on this system.")
			}

			for _, process := range processes {
				processScanStartTime := time.Now()
				libraries, harderror, softerrors := lib.GetLibrariesForPid((*process).GetId(), true)
				processScanEndTime := time.Now()
				if harderror != nil {
					log.WithError(harderror).Error("Unable to list libraries for Process: %v", process)
					continue
				}

				for _, softerr := range softerrors {
					log.WithError(softerr).Warning("[Non-Critical] Error when listing libraries for Process: %v", process)
				}

				scanLogger.
					WithField("StartTime", processScanStartTime).
					WithField("EndTime", processScanEndTime).
					WithField("Duration", processScanEndTime.Sub(processScanStartTime)).
					WithField("Process", process).
					WithField("Libraries", libraries).
					Info("ProcessScan")
			}
		}

		processListScanEndTime := time.Now()
		scanLogger.
			WithField("StartTime", processListScanStartTime).
			WithField("EndTime", processListScanEndTime).
			WithField("Duration", processListScanEndTime.Sub(processListScanStartTime)).
			Info("ProcessListScan")
	}
}

func isBlackListed(path string) bool {
	for _, blacklisted := range FileScanBlacklist {
		if path == blacklisted {
			return true
		}
	}

	return false
}
