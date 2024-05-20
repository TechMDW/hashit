package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TechMDW/hashit/pkg/hash"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "hashit [string]",
	Example: "  hashit \"Hello, World!\" \n  hashit \"Hello, World!\" -t md5 \n  hashit -f /path/to/file\n  hashit -f /path/to/file -t sha256",
	Short:   "Hash a file using multiple hash functions",
	Long:    `Hash a file using Adler, MD4, MD5, SHA1, SHA2, SHA3, FNV and CRC hash functions.`,
	Run:     hashRun,
	Args:    cobra.MaximumNArgs(2),
}

func hashRun(cmd *cobra.Command, args []string) {
	filePath, _ := cmd.Flags().GetString("file")
	hashType, _ := cmd.Flags().GetString("type")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	var isFile bool
	if filePath != "" {
		isFile = true
	}

	if !isFile && len(args) <= 0 {
		cmd.Help()
		return
	}

	var data []byte
	if isFile {
		data = []byte(filePath)
	} else {
		data = []byte(args[0])
	}

	if hashType != "" {
		hash, err := hash.ComputeHash(data, hashType, isFile)
		if err != nil {
			cmd.PrintErr(err)
			return
		}

		if jsonOutput {
			j, err := json.MarshalIndent(hash, "", "  ")
			if err != nil {
				cmd.PrintErr(err)
				return
			}
			cmd.Println(string(j))
		} else {
			cmd.Println(hash.HexDigest)
		}
		return
	}

	var hashes hash.Hashes
	var err error
	if isFile {
		hashes, err = hash.HasherMultiFile(string(data))
	} else {
		hashes, err = hash.HasherMulti(data)
	}
	if err != nil {
		cmd.PrintErr(err)
		return
	}

	if jsonOutput {
		j, err := json.MarshalIndent(hashes, "", "  ")
		if err != nil {
			cmd.PrintErr(err)
			return
		}

		cmd.Println(string(j))
		return
	} else {
		for _, h := range hashes.Array() {
			cmd.Printf("%s: %s\n", h.Type, h.Hash)
		}
	}

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("file", "f", "", "File to hash")
	rootCmd.Flags().StringP("type", "t", "", "Type of hash function to use")
	rootCmd.Flags().BoolP("json", "j", false, "Output as JSON")
}
