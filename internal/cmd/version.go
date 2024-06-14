package cmd

import (
	"fmt"

	"github.com/TechMDW/hashit/internal/version"
	"github.com/spf13/cobra"
)

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of hashit",
	Long:  `Print the version number of hashit.`,
	Run:   versionRun,
}

func versionRun(cmd *cobra.Command, args []string) {
	cmd.Println(fmt.Sprintf("hashit version: %s", version.Version))
	cmd.Println(fmt.Sprintf("Go version:     %s", version.GoVersion))
}

func init() {
	rootCmd.AddCommand(VersionCmd)
}
