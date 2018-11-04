package cmd

import (
	"github.com/polyverse/ropoly/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var ServerAddress string

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringVarP(&ServerAddress, "address", "a", ":8008", "The Address at which to host the HTTP server.")
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run Ropoly as a webserver.",
	Long:  `Run Ropoly as a webserver that can be scraped for information about the system (that Ropoly has permissions to.)`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Infof("Starting a blocking webserver at address %s", ServerAddress)
		server.ServeOverHttp(ServerAddress)
	},
}
