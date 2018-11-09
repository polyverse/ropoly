package cmd

import (
	"github.com/polyverse/ropoly/server"
	"github.com/polyverse/ropoly/lib"
	"github.com/polyverse/ropoly/handlers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	ServerAddress  string
	VerboseLogging bool
	dataDirectory string
)

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringVarP(&ServerAddress, "address", "a", ":8008", "The Address at which to host the HTTP server.")
	serverCmd.Flags().BoolVarP(&VerboseLogging, "verbose", "v", false, "Enable debug-level verbose logging.")
	//serverCmd.Flags().StringVarP(&dataDirectory, "directory", "d", "", "Directory on for storing persistent data.")
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run Ropoly as a webserver.",
	Long:  `Run Ropoly as a webserver that can be scraped for information about the system (that Ropoly has permissions to.)`,
	Run: func(cmd *cobra.Command, args []string) {
		if VerboseLogging {
			log.Infof("Enabling verbose debug-level logging...")
			log.SetLevel(log.DebugLevel)
			log.SetReportCaller(true)
		}

		// TODO: Change this later.
		dataDirectory = "/go/src/github.com/polyverse/ropoly/PersistentData"

		if dataDirectory != "" {
			err := lib.EnsureDirectory(dataDirectory)
			if err != nil {
				log.Error(err)
				log.Info("Setting persistent data directory to none.")
			}
		}
		handlers.DataDirectory = dataDirectory

		log.Infof("Starting a blocking webserver at address %s", ServerAddress)
		server.ServeOverHttp(ServerAddress)
	},
}
