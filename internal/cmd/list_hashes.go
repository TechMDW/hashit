package cmd

import (
	"github.com/TechMDW/hashit/pkg/hash"
	"github.com/spf13/cobra"
)

var listHashesCmd = &cobra.Command{
	Use:   "list-hashes",
	Short: "List all available hash functions",
	Long:  `List all available hash functions that can be used with the hash command.`,
	Run:   listHashesRun,
}

func listHashesRun(cmd *cobra.Command, args []string) {
	availableHashes := hash.ComputeHashList()
	cmd.Println("Available hash functions:")
	for _, hashType := range availableHashes {
		cmd.Println("-", hashType)
	}
}

func init() {
	rootCmd.AddCommand(listHashesCmd)
}
