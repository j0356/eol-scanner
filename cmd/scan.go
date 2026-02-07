package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/j0356/eol-scanner/core/scanning"
	"github.com/spf13/cobra"
)

// Scan flags
var (
	sourceType        string
	forwardLookupDays int
	outputFormat      string
	noUpdateDB        bool
	onlyEOL           bool
	registryUser      string
	registryPass      string
)

var scanCmd = &cobra.Command{
	Use:   "scan [image]",
	Short: "Scan a container image for EOL components",
	Long: `Scan a container image to identify components that have reached
or are approaching end-of-life status.

The scan will:
1. Check if the EOL database exists and is up-to-date
2. Generate an SBOM from the container image
3. Compare detected packages against the EOL database
4. Report components that are EOL or approaching EOL

Examples:
  # Scan a local Docker image
  eol-scanner scan nginx:latest

  # Scan from a container registry
  eol-scanner scan --source registry ghcr.io/org/image:tag

  # Scan a tar archive
  eol-scanner scan --source tar ./image.tar

  # Check for EOL within 180 days
  eol-scanner scan --days 180 python:3.9

  # Output as JSON
  eol-scanner scan --output json alpine:latest

  # Show only EOL components
  eol-scanner scan --only-eol ubuntu:20.04`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&sourceType, "source", "s", "docker", "Image source type: docker, registry, tar")
	scanCmd.Flags().IntVarP(&forwardLookupDays, "days", "d", 90, "Forward lookup days for upcoming EOL")
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json")
	scanCmd.Flags().BoolVar(&noUpdateDB, "no-update", false, "Skip automatic database update")
	scanCmd.Flags().BoolVar(&onlyEOL, "only-eol", false, "Only show EOL and EOL-soon components")
	scanCmd.Flags().StringVar(&registryUser, "registry-user", "", "Registry username for authentication")
	scanCmd.Flags().StringVar(&registryPass, "registry-pass", "", "Registry password for authentication")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	imageRef := args[0]
	ctx := context.Background()

	// Build scanner config
	config := &scanning.ScannerConfig{
		DBPath:            dbPath,
		ForwardLookupDays: forwardLookupDays,
		AutoUpdateDB:      !noUpdateDB,
		DBMaxAge: 7 * 24 * time.Hour,
	}

	// Add progress callback if verbose
	if verbose {
		config.ProgressCallback = func(stage, message string) {
			fmt.Printf("[%s] %s\n", stage, message)
		}
	}

	// Create scanner
	scanner, err := scanning.NewScanner(config)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}
	defer scanner.Close()

	// Run scan based on source type
	var summary *scanning.ScanSummary
	switch strings.ToLower(sourceType) {
	case "docker":
		if verbose {
			fmt.Printf("Scanning Docker image: %s\n", imageRef)
		}
		summary, err = scanner.ScanFromDocker(ctx, imageRef)
	case "registry":
		if verbose {
			fmt.Printf("Scanning registry image: %s\n", imageRef)
		}
		summary, err = scanner.ScanFromRegistry(ctx, imageRef)
	case "tar":
		if verbose {
			fmt.Printf("Scanning tar archive: %s\n", imageRef)
		}
		summary, err = scanner.ScanFromTar(ctx, imageRef)
	default:
		return fmt.Errorf("unknown source type: %s (use: docker, registry, tar)", sourceType)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	switch strings.ToLower(outputFormat) {
	case "json":
		return outputJSON(summary)
	case "table":
		return outputTable(summary)
	default:
		return fmt.Errorf("unknown output format: %s (use: table, json)", outputFormat)
	}
}

func outputJSON(summary *scanning.ScanSummary) error {
	var output interface{}
	if onlyEOL {
		output = struct {
			*scanning.ScanSummary
			Components []scanning.ComponentResult `json:"components"`
		}{
			ScanSummary: summary,
			Components:  summary.GetEOLComponents(),
		}
	} else {
		output = summary
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputTable(summary *scanning.ScanSummary) error {
	// Print header
	fmt.Printf("\nEOL Scan Results for: %s\n", summary.ImageReference)
	fmt.Printf("Scan Time: %s\n", summary.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("Forward Lookup: %d days\n", summary.ForwardLookupDays)
	fmt.Println(strings.Repeat("-", 80))

	// Print summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total Components:   %d\n", summary.TotalComponents)
	fmt.Printf("  EOL Components:     %d\n", summary.EOLComponents)
	fmt.Printf("  EOL Soon:           %d\n", summary.EOLSoonComponents)
	fmt.Printf("  Active:             %d\n", summary.ActiveComponents)
	fmt.Printf("  Unknown:            %d\n", summary.UnknownComponents)

	// Get components to display
	var components []scanning.ComponentResult
	if onlyEOL {
		components = summary.GetEOLComponents()
	} else {
		components = summary.Components
	}

	if len(components) == 0 {
		if onlyEOL {
			fmt.Println("\nNo EOL or EOL-soon components found.")
		}
		return nil
	}

	// Print component details
	fmt.Printf("\nComponents:\n")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-30s %-15s %-10s %-12s %s\n", "NAME", "VERSION", "STATUS", "EOL DATE", "DAYS LEFT")
	fmt.Println(strings.Repeat("-", 80))

	for _, c := range components {
		name := truncate(c.Name, 30)
		version := truncate(c.Version, 15)
		status := statusSymbol(c.Status)
		eolDate := c.EOLDate
		if eolDate == "" {
			eolDate = "-"
		}
		daysLeft := "-"
		if c.DaysUntilEOL != nil {
			daysLeft = fmt.Sprintf("%d", *c.DaysUntilEOL)
		}

		fmt.Printf("%-30s %-15s %-10s %-12s %s\n", name, version, status, eolDate, daysLeft)
	}

	fmt.Println(strings.Repeat("-", 80))

	// Exit code hint
	if summary.EOLComponents > 0 {
		fmt.Printf("\nWarning: %d component(s) have reached end-of-life!\n", summary.EOLComponents)
	}
	if summary.EOLSoonComponents > 0 {
		fmt.Printf("Notice: %d component(s) will reach EOL within %d days.\n", summary.EOLSoonComponents, summary.ForwardLookupDays)
	}

	return nil
}

func statusSymbol(status scanning.EOLStatus) string {
	switch status {
	case scanning.StatusEOL:
		return "EOL"
	case scanning.StatusEOLSoon:
		return "EOL-SOON"
	case scanning.StatusActive:
		return "ACTIVE"
	case scanning.StatusUnknown:
		return "UNKNOWN"
	default:
		return string(status)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
