package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// Version information (set via ldflags)
var (
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

// Global flags
var (
	dbPath  string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "eol-scanner",
	Short: "Scan container images for end-of-life components",
	Long: `EOL Scanner analyzes container images to identify components
that have reached or are approaching end-of-life status.

It generates an SBOM (Software Bill of Materials) from container images
and compares the detected packages against the endoflife.date database
to identify EOL risks.

Examples:
  # Scan a Docker image
  eol-scanner scan nginx:latest

  # Scan from a registry
  eol-scanner scan --source registry ghcr.io/org/image:tag

  # Scan with forward-looking EOL check (180 days)
  eol-scanner scan --days 180 python:3.9

  # Sync the EOL database
  eol-scanner db sync

  # Show database statistics
  eol-scanner db stats`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "Custom database path (default: ~/eol-db/eol.db)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
