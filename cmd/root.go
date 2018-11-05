package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "ropoly",
	Short: "Ropoly is a Rop gadget analysis tool",
	Long: `Ropoly can operate as an interactive RESTful API server,
             or as a passive scanner daemon.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
