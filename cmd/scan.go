package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/j0356/eol-scanner/core/scanning"
	sbomgen "github.com/j0356/eol-scanner/core/sbom"
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
	registryToken     string
	registryCert      string
	registryKey       string
	registryCA        string
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
	scanCmd.Flags().StringVar(&registryToken, "registry-token", "", "Registry token for token-based authentication")
	scanCmd.Flags().StringVar(&registryCert, "registry-cert", "", "Client certificate path for mTLS authentication")
	scanCmd.Flags().StringVar(&registryKey, "registry-key", "", "Client key path for mTLS authentication")
	scanCmd.Flags().StringVar(&registryCA, "registry-ca", "", "Custom CA certificate file or directory")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	imageRef := args[0]
	ctx := context.Background()

	// High-level progress indicator (always shown)
	fmt.Printf("📋 Initializing EOL scanner...\n")

	// Build scanner config
	config := &scanning.ScannerConfig{
		DBPath:            dbPath,
		ForwardLookupDays: forwardLookupDays,
		AutoUpdateDB:      !noUpdateDB,
		DBMaxAge:          7 * 24 * time.Hour,
	}

	// Build registry credentials if any auth flags are provided
	if registryUser != "" || registryToken != "" || registryCert != "" || registryCA != "" {
		config.RegistryAuth = &sbomgen.RegistryCredentials{
			Username:   registryUser,
			Password:   registryPass,
			Token:      registryToken,
			ClientCert: registryCert,
			ClientKey:  registryKey,
		}
		config.RegistryCAFileOrDir = registryCA
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

	// High-level progress: SBOM generation
	fmt.Printf("🔍 Generating SBOM for %s...\n", imageRef)

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

	// High-level progress: analysis complete
	fmt.Printf("✅ Analysis complete. Found %d components.\n", summary.TotalComponents)

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
	fmt.Printf("\n🔍 EOL Scan Results for: %s\n", summary.ImageReference)
	fmt.Printf("   Scan Time: %s\n", summary.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Forward Lookup: %d days\n", summary.ForwardLookupDays)
	fmt.Println(strings.Repeat("─", 85))

	// Print summary
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   Total Components: %d\n", summary.TotalComponents)
	fmt.Printf("   ❌ EOL:            %d\n", summary.EOLComponents)
	fmt.Printf("   ⚠️ EOL Soon:       %d\n", summary.EOLSoonComponents)
	fmt.Printf("   ✅ Active:         %d\n", summary.ActiveComponents)
	fmt.Printf("   ❓ Unknown:        %d\n", summary.UnknownComponents)

	// Get components to display
	var components []scanning.ComponentResult
	if onlyEOL {
		components = summary.GetEOLComponents()
	} else {
		components = summary.Components
	}

	if len(components) == 0 {
		if onlyEOL {
			fmt.Println("\n✅ No EOL or EOL-soon components found.")
		}
		return nil
	}

	// Print component details
	fmt.Printf("\n📦 Components:\n")
	fmt.Println(strings.Repeat("─", 90))
	fmt.Printf("%-32s %-18s %-8s  %-12s %s\n", "NAME", "VERSION", "STATUS", "EOL DATE", "DAYS")
	fmt.Println(strings.Repeat("─", 90))

	for _, c := range components {
		name := truncate(c.Name, 32)
		version := truncate(c.Version, 18)
		statusIcon, statusText := statusParts(c.Status)
		eolDate := formatEOLDate(c.EOLDate)
		daysLeft := "-"
		if c.DaysUntilEOL != nil {
			daysLeft = fmt.Sprintf("%d", *c.DaysUntilEOL)
		}

		fmt.Printf("%-32s %-18s %s %-6s %-12s %s\n", name, version, statusIcon, statusText, eolDate, daysLeft)
	}

	fmt.Println(strings.Repeat("─", 85))

	// Exit code hint
	if summary.EOLComponents > 0 {
		fmt.Printf("\n⚠️ Warning: %d component(s) have reached end-of-life!\n", summary.EOLComponents)
	}
	if summary.EOLSoonComponents > 0 {
		fmt.Printf("📅 Notice: %d component(s) will reach EOL within %d days.\n", summary.EOLSoonComponents, summary.ForwardLookupDays)
	}
	if summary.EOLComponents == 0 && summary.EOLSoonComponents == 0 {
		fmt.Printf("\n✅ No end-of-life issues detected.\n")
	}

	return nil
}

func statusParts(status scanning.EOLStatus) (string, string) {
	switch status {
	case scanning.StatusEOL:
		return "❌", "EOL"
	case scanning.StatusEOLSoon:
		return "⚠️", "SOON"
	case scanning.StatusActive:
		return "✅", "OK"
	case scanning.StatusUnknown:
		return "❓", "N/A"
	default:
		return " ", string(status)
	}
}

func formatEOLDate(date string) string {
	if date == "" {
		return "-"
	}
	// Try to parse and format nicely (remove time portion)
	if len(date) >= 10 {
		return date[:10]
	}
	return date
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
