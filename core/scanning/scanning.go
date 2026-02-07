package scanning

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/j0356/eol-scanner/core/db"
	sbomgen "github.com/j0356/eol-scanner/core/sbom"
)

// EOLStatus represents the EOL status of a component
type EOLStatus string

const (
	StatusActive         EOLStatus = "active"
	StatusEOL            EOLStatus = "eol"
	StatusEOLSoon        EOLStatus = "eol_soon"
	StatusUnknown        EOLStatus = "unknown"
	DefaultDBMaxAge                = 7 * 24 * time.Hour// 1 week
	DefaultForwardLookup           = 90                 // 90 days default forward lookup
)

// ComponentResult represents the scan result for a single component
type ComponentResult struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	PURL           string    `json:"purl"`
	Type           string    `json:"type"`
	Status         EOLStatus `json:"status"`
	EOLDate        string    `json:"eol_date,omitempty"`
	DaysUntilEOL   *int      `json:"days_until_eol,omitempty"`
	MatchedProduct string    `json:"matched_product,omitempty"`
	MatchedCycle   string    `json:"matched_cycle,omitempty"`
	LatestVersion  string    `json:"latest_version,omitempty"`
	IsLTS          bool      `json:"is_lts"`
}

// OSInfo represents the operating system EOL information
type OSInfo struct {
	Name           string    `json:"name"`
	ID             string    `json:"id"`
	Version        string    `json:"version"`
	VersionID      string    `json:"version_id"`
	PrettyName     string    `json:"pretty_name"`
	Status         EOLStatus `json:"status"`
	EOLDate        string    `json:"eol_date,omitempty"`
	DaysUntilEOL   *int      `json:"days_until_eol,omitempty"`
	MatchedProduct string    `json:"matched_product,omitempty"`
	MatchedCycle   string    `json:"matched_cycle,omitempty"`
	IsLTS          bool      `json:"is_lts"`
}

// ScanSummary contains the overall scan results
type ScanSummary struct {
	TotalComponents   int               `json:"total_components"`
	EOLComponents     int               `json:"eol_components"`
	EOLSoonComponents int               `json:"eol_soon_components"`
	ActiveComponents  int               `json:"active_components"`
	UnknownComponents int               `json:"unknown_components"`
	Components        []ComponentResult `json:"components"`
	OS                *OSInfo           `json:"os,omitempty"`
	ScanTime          time.Time         `json:"scan_time"`
	ImageReference    string            `json:"image_reference"`
	DBLastUpdated     string            `json:"db_last_updated"`
	ForwardLookupDays int               `json:"forward_lookup_days"`
}

// ScannerConfig holds configuration for the scanner
type ScannerConfig struct {
	DBPath            string                        // Custom DB path (empty for default)
	DBMaxAge          time.Duration                 // Max age before DB refresh
	ForwardLookupDays int                           // Days to look ahead for upcoming EOL
	AutoUpdateDB      bool                          // Automatically update DB if stale
	Categories        []string                      // Categories to sync
	RegistryAuth      *sbomgen.RegistryCredentials  // Registry credentials
	ProgressCallback  func(stage, message string)   // Progress callback
}

// DefaultScannerConfig returns the default scanner configuration
func DefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		DBMaxAge:          DefaultDBMaxAge,
		ForwardLookupDays: DefaultForwardLookup,
		AutoUpdateDB:      true,
		Categories:        db.DefaultCategories,
	}
}

// Scanner performs EOL scanning on container images
type Scanner struct {
	config    *ScannerConfig
	dbManager *db.EOLDatabaseManager
	generator *sbomgen.Generator
}

// NewScanner creates a new Scanner with the given configuration
func NewScanner(config *ScannerConfig) (*Scanner, error) {
	if config == nil {
		config = DefaultScannerConfig()
	}

	scanner := &Scanner{
		config: config,
	}

	// Initialize SBOM generator
	generator := sbomgen.NewGenerator()
	if config.RegistryAuth != nil {
		generator = generator.WithCredentials(
			config.RegistryAuth.Authority,
			config.RegistryAuth.Username,
			config.RegistryAuth.Password,
		)
	}
	if config.ProgressCallback != nil {
		generator = generator.WithProgress(config.ProgressCallback)
	}
	scanner.generator = generator

	return scanner, nil
}

// Close closes the scanner and releases resources
func (s *Scanner) Close() error {
	if s.dbManager != nil {
		return s.dbManager.Close()
	}
	return nil
}

// progress reports progress if callback is set
func (s *Scanner) progress(stage, message string) {
	if s.config.ProgressCallback != nil {
		s.config.ProgressCallback(stage, message)
	}
}

// ensureDatabase ensures the database is available and up-to-date
func (s *Scanner) ensureDatabase(ctx context.Context) error {
	s.progress("db", "Checking EOL database...")

	var dbPath string
	var err error

	if s.config.DBPath != "" {
		dbPath = s.config.DBPath
	} else {
		dbPath, err = db.DefaultDBPath()
		if err != nil {
			return fmt.Errorf("failed to get default DB path: %w", err)
		}
	}

	// Check if DB exists
	dbExists := true
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		dbExists = false
	}

	// Open or create the database
	s.dbManager, err = db.NewEOLDatabaseManager(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// If DB doesn't exist or auto-update is enabled, check if we need to sync
	if !dbExists {
		s.progress("db", "Database not found, performing initial sync...")
		return s.syncDatabase(ctx)
	}

	if s.config.AutoUpdateDB {
		needsUpdate, err := s.checkDBNeedsUpdate()
		if err != nil {
			return err
		}
		if needsUpdate {
			s.progress("db", "Database is stale, updating...")
			return s.syncDatabase(ctx)
		}
	}

	s.progress("db", "Database is up-to-date")
	return nil
}

// checkDBNeedsUpdate checks if the database needs updating
func (s *Scanner) checkDBNeedsUpdate() (bool, error) {
	stats, err := s.dbManager.GetStats()

	// Parse the last sync time
	lastSync, err := time.Parse(time.RFC3339, stats.LastFullSync.String)
	if err != nil {
		return true, nil // Can't parse, assume needs update
	}

	// Check if older than max age
	return time.Since(lastSync) > s.config.DBMaxAge, nil
}

// syncDatabase performs a full sync of the database
func (s *Scanner) syncDatabase(ctx context.Context) error {
	s.progress("db", "Syncing EOL database from endoflife.date API...")

	result, err := s.dbManager.FullSync(ctx, s.config.Categories)
	if err != nil {
		return fmt.Errorf("failed to sync database: %w", err)
	}

	s.progress("db", fmt.Sprintf("Synced %d products, %d cycles, %d identifiers",
		result.ProductsProcessed, result.CyclesProcessed, result.IdentifiersProcessed))

	return nil
}

// ScanFromTar scans a container image from a tar archive
func (s *Scanner) ScanFromTar(ctx context.Context, tarPath string) (*ScanSummary, error) {
	if err := s.ensureDatabase(ctx); err != nil {
		return nil, err
	}

	s.progress("sbom", "Generating SBOM from tar archive...")
	sbomResult, err := s.generator.GenerateFromTar(ctx, tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return s.analyzeSBOM(sbomResult, tarPath)
}

// ScanFromRegistry scans a container image from a registry
func (s *Scanner) ScanFromRegistry(ctx context.Context, imageRef string) (*ScanSummary, error) {
	if err := s.ensureDatabase(ctx); err != nil {
		return nil, err
	}

	s.progress("sbom", "Generating SBOM from registry image...")
	sbomResult, err := s.generator.GenerateFromRegistry(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return s.analyzeSBOM(sbomResult, imageRef)
}

// ScanFromDocker scans a container image from the local Docker daemon
func (s *Scanner) ScanFromDocker(ctx context.Context, imageRef string) (*ScanSummary, error) {
	if err := s.ensureDatabase(ctx); err != nil {
		return nil, err
	}

	s.progress("sbom", "Generating SBOM from Docker image...")
	sbomResult, err := s.generator.GenerateFromDocker(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return s.analyzeSBOM(sbomResult, imageRef)
}

// analyzeSBOM analyzes the SBOM and checks components against EOL database
func (s *Scanner) analyzeSBOM(sbomResult *sbom.SBOM, imageRef string) (*ScanSummary, error) {
	s.progress("analyze", "Analyzing components for EOL status...")

	summary := &ScanSummary{
		ScanTime:          time.Now(),
		ImageReference:    imageRef,
		ForwardLookupDays: s.config.ForwardLookupDays,
		Components:        make([]ComponentResult, 0),
	}

	// Get DB last updated time
	stats, err := s.dbManager.GetStats()
	if err == nil && stats.LastFullSync.Valid {
		summary.DBLastUpdated = stats.LastFullSync.String
	}

	// Check OS/Distribution EOL status and add as first component
	if sbomResult.Artifacts.LinuxDistribution != nil {
		osInfo := s.checkOSEOL(sbomResult.Artifacts.LinuxDistribution)
		if osInfo != nil {
			summary.OS = osInfo
			// Add OS as a component
			osComponent := ComponentResult{
				Name:           osInfo.PrettyName,
				Version:        osInfo.VersionID,
				Type:           "os",
				Status:         osInfo.Status,
				EOLDate:        osInfo.EOLDate,
				DaysUntilEOL:   osInfo.DaysUntilEOL,
				MatchedProduct: osInfo.MatchedProduct,
				MatchedCycle:   osInfo.MatchedCycle,
				IsLTS:          osInfo.IsLTS,
			}
			if osComponent.Name == "" {
				osComponent.Name = fmt.Sprintf("%s %s", osInfo.Name, osInfo.Version)
			}
			if osComponent.Version == "" {
				osComponent.Version = osInfo.Version
			}
			summary.Components = append(summary.Components, osComponent)
			summary.TotalComponents++
			switch osComponent.Status {
			case StatusEOL:
				summary.EOLComponents++
			case StatusEOLSoon:
				summary.EOLSoonComponents++
			case StatusActive:
				summary.ActiveComponents++
			case StatusUnknown:
				summary.UnknownComponents++
			}
		}
	}

	// Extract packages from SBOM
	packages := sbomResult.Artifacts.Packages.Sorted()

	for _, p := range packages {
		result := s.checkComponent(p)
		summary.Components = append(summary.Components, result)

		// Update counts
		summary.TotalComponents++
		switch result.Status {
		case StatusEOL:
			summary.EOLComponents++
		case StatusEOLSoon:
			summary.EOLSoonComponents++
		case StatusActive:
			summary.ActiveComponents++
		case StatusUnknown:
			summary.UnknownComponents++
		}
	}

	s.progress("done", fmt.Sprintf("Scan complete: %d total, %d EOL, %d EOL soon",
		summary.TotalComponents, summary.EOLComponents, summary.EOLSoonComponents))

	return summary, nil
}

// checkComponent checks a single component against the EOL database
func (s *Scanner) checkComponent(p pkg.Package) ComponentResult {
	result := ComponentResult{
		Name:    p.Name,
		Version: p.Version,
		Type:    string(p.Type),
		Status:  StatusUnknown,
	}

	// Get PURL if available
	if p.PURL != "" {
		result.PURL = p.PURL
	}

	// Try to look up by exact PURL first
	if result.PURL != "" {
		product, cycles, _, err := s.dbManager.LookupByPURL(result.PURL)
		if err == nil && product != nil {
			result.MatchedProduct = product.Name
			result = s.evaluateEOLStatus(result, cycles, p.Version)
			return result
		}
	}

	// For deb/rpm packages, try distro-specific PURL lookup
	// Database has entries like pkg:deb/debian/nginx, pkg:deb/ubuntu/python3.12
	if string(p.Type) == "deb" {
		for _, distro := range []string{"debian", "ubuntu"} {
			product, cycles, err := s.dbManager.LookupByPURLPrefix("deb/"+distro, p.Name)
			if err == nil && product != nil {
				result.MatchedProduct = product.Name
				result = s.evaluateEOLStatus(result, cycles, p.Version)
				return result
			}
		}
	} else if string(p.Type) == "rpm" {
		for _, distro := range []string{"fedora", "redhat", "centos", "amzn"} {
			product, cycles, err := s.dbManager.LookupByPURLPrefix("rpm/"+distro, p.Name)
			if err == nil && product != nil {
				result.MatchedProduct = product.Name
				result = s.evaluateEOLStatus(result, cycles, p.Version)
				return result
			}
		}
	} else if string(p.Type) == "apk" {
		product, cycles, err := s.dbManager.LookupByPURLPrefix("apk/alpine", p.Name)
		if err == nil && product != nil {
			result.MatchedProduct = product.Name
			result = s.evaluateEOLStatus(result, cycles, p.Version)
			return result
		}
	}

	// Try PURL type lookup for language packages (pypi, npm, gem, etc.)
	purlType := getPURLTypeFromPackageType(string(p.Type))
	if purlType != "" {
		product, cycles, err := s.dbManager.LookupByPURLPrefix(purlType, p.Name)
		if err == nil && product != nil {
			result.MatchedProduct = product.Name
			result = s.evaluateEOLStatus(result, cycles, p.Version)
			return result
		}
	}

	// Try generic PURL lookup
	product, cycles, err := s.dbManager.LookupByPURLPrefix("generic", p.Name)
	if err == nil && product != nil {
		result.MatchedProduct = product.Name
		result = s.evaluateEOLStatus(result, cycles, p.Version)
		return result
	}

	// Try CPE matching if package has CPEs
	if len(p.CPEs) > 0 {
		for _, c := range p.CPEs {
			cpeStr := c.Attributes.String()
			product, cycles, err := s.dbManager.LookupByCPE(cpeStr)
			if err == nil && product != nil {
				result.MatchedProduct = product.Name
				result = s.evaluateEOLStatus(result, cycles, p.Version)
				return result
			}
		}
	}

	// Fallback: try to look up by package name (for products like nginx, postgresql, etc.)
	product, cycles, err = s.dbManager.LookupByName(p.Name, string(p.Type))
	if err == nil && product != nil {
		result.MatchedProduct = product.Name
		result = s.evaluateEOLStatus(result, cycles, p.Version)
	}

	return result
}

// checkOSEOL checks the operating system EOL status
func (s *Scanner) checkOSEOL(distro *linux.Release) *OSInfo {
	if distro == nil {
		return nil
	}

	osInfo := &OSInfo{
		Name:       distro.Name,
		ID:         distro.ID,
		Version:    distro.Version,
		VersionID:  distro.VersionID,
		PrettyName: distro.PrettyName,
		Status:     StatusUnknown,
	}

	// Map distro ID to product name in EOL database
	productName := mapDistroToProduct(distro.ID)
	if productName == "" {
		return osInfo
	}

	// Look up the OS in the database
	product, cycles, err := s.dbManager.LookupByName(productName, "os")
	if err != nil || product == nil {
		return osInfo
	}

	osInfo.MatchedProduct = product.Name

	// Find matching cycle based on version
	versionToMatch := distro.VersionID
	if versionToMatch == "" {
		versionToMatch = distro.Version
	}

	// Evaluate EOL status using the same logic as components
	result := ComponentResult{
		Name:    osInfo.Name,
		Version: versionToMatch,
		Status:  StatusUnknown,
	}
	result = s.evaluateEOLStatus(result, cycles, versionToMatch)

	osInfo.Status = result.Status
	osInfo.EOLDate = result.EOLDate
	osInfo.DaysUntilEOL = result.DaysUntilEOL
	osInfo.MatchedCycle = result.MatchedCycle
	osInfo.IsLTS = result.IsLTS

	return osInfo
}

// mapDistroToProduct maps Linux distribution IDs to endoflife.date product names
func mapDistroToProduct(distroID string) string {
	// Map common distro IDs to their product names in endoflife.date
	distroMap := map[string]string{
		"debian":       "debian",
		"ubuntu":       "ubuntu",
		"alpine":       "alpine-linux",
		"centos":       "centos",
		"rhel":         "rhel",
		"fedora":       "fedora",
		"amzn":         "amazon-linux",
		"amazonlinux":  "amazon-linux",
		"almalinux":    "almalinux",
		"rocky":        "rocky-linux",
		"opensuse":     "opensuse",
		"sles":         "sles",
		"ol":           "oracle-linux",
		"oraclelinux":  "oracle-linux",
		"arch":         "arch",
		"manjaro":      "manjaro",
		"linuxmint":    "linuxmint",
		"pop":          "pop-os",
		"elementary":   "elementary-os",
		"nixos":        "nixos",
		"void":         "void-linux",
		"gentoo":       "gentoo",
		"slackware":    "slackware",
		"photon":       "photon",
		"clear-linux":  "clear-linux",
		"flatcar":      "flatcar",
	}

	if product, ok := distroMap[strings.ToLower(distroID)]; ok {
		return product
	}

	// Try the ID directly as it might match
	return distroID
}

// parseEOLDate parses EOL date strings in various formats
func parseEOLDate(dateStr string) (time.Time, error) {
	// Try multiple date formats
	formats := []string{
		time.RFC3339,           // 2006-01-02T15:04:05Z07:00
		"2006-01-02T15:04:05Z", // ISO 8601 with Z
		"2006-01-02",           // Simple date
	}
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// getPURLTypeFromPackageType maps Syft package types to PURL types
func getPURLTypeFromPackageType(pkgType string) string {
	typeMap := map[string]string{
		"python":         "pypi",
		"gem":            "gem",
		"npm":            "npm",
		"go-module":      "golang",
		"cargo":          "cargo",
		"pub":            "pub",
		"hex":            "hex",
		"cocoapods":      "cocoapods",
		"hackage":        "hackage",
		"java-archive":   "maven",
		"jenkins-plugin": "maven",
		"nuget":          "nuget",
		"composer":       "composer",
		"conan":          "conan",
		"apk":            "apk",
		"deb":            "deb",
		"rpm":            "rpm",
	}
	return typeMap[pkgType]
}

// evaluateEOLStatus determines the EOL status based on cycles
func (s *Scanner) evaluateEOLStatus(result ComponentResult, cycles []db.Cycle, version string) ComponentResult {
	if len(cycles) == 0 {
		return result
	}

	today := time.Now()
	forwardDate := today.AddDate(0, 0, s.config.ForwardLookupDays)

	// Try to find a matching cycle based on version
	var matchedCycle *db.Cycle
	for i, cycle := range cycles {
		// Check if the version matches or starts with the cycle name
		if matchesVersion(version, cycle.Cycle) {
			matchedCycle = &cycles[i]
			break
		}
	}

	// If no specific match, use the first cycle as a reference
	if matchedCycle == nil && len(cycles) > 0 {
		// Try to match major version
		for i, cycle := range cycles {
			if matchesMajorVersion(version, cycle.Cycle) {
				matchedCycle = &cycles[i]
				break
			}
		}
	}

	if matchedCycle == nil {
		return result
	}

	result.MatchedCycle = matchedCycle.Cycle
	result.IsLTS = matchedCycle.LTS == 1

	if matchedCycle.LatestVersion.Valid {
		result.LatestVersion = matchedCycle.LatestVersion.String
	}

	// Check EOL status
	if matchedCycle.EOLBoolean.Valid && matchedCycle.EOLBoolean.Int64 == 1 {
		// Boolean EOL - already EOL
		result.Status = StatusEOL
		return result
	}

	if matchedCycle.EOL.Valid && matchedCycle.EOL.String != "" {
		eolDate, err := parseEOLDate(matchedCycle.EOL.String)
		if err == nil {
			result.EOLDate = matchedCycle.EOL.String

			if eolDate.Before(today) || eolDate.Equal(today) {
				result.Status = StatusEOL
			} else if eolDate.Before(forwardDate) {
				result.Status = StatusEOLSoon
				days := int(eolDate.Sub(today).Hours() / 24)
				result.DaysUntilEOL = &days
			} else {
				result.Status = StatusActive
				days := int(eolDate.Sub(today).Hours() / 24)
				result.DaysUntilEOL = &days
			}
			return result
		}
	}

	// If we have a matched cycle but no EOL info, mark as active
	if matchedCycle.IsMaintained == 1 {
		result.Status = StatusActive
	}

	return result
}

// matchesVersion checks if a version matches a cycle
func matchesVersion(version, cycle string) bool {
	// Exact match
	if version == cycle {
		return true
	}

	// Version starts with cycle (e.g., "3.9.1" matches cycle "3.9")
	if strings.HasPrefix(version, cycle+".") || strings.HasPrefix(version, cycle+"-") {
		return true
	}

	return false
}

// matchesMajorVersion checks if version's major component matches cycle
func matchesMajorVersion(version, cycle string) bool {
	// Extract major version from both
	vMajor := extractMajorVersion(version)
	cMajor := extractMajorVersion(cycle)

	return vMajor != "" && vMajor == cMajor
}

// extractMajorVersion extracts the major version component
func extractMajorVersion(version string) string {
	// Remove leading 'v' if present
	v := strings.TrimPrefix(version, "v")

	// Split by common delimiters
	for _, sep := range []string{".", "-", "_"} {
		parts := strings.Split(v, sep)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return v
}

// GetEOLComponents returns only the components that are EOL or EOL soon
func (summary *ScanSummary) GetEOLComponents() []ComponentResult {
	var results []ComponentResult
	for _, c := range summary.Components {
		if c.Status == StatusEOL || c.Status == StatusEOLSoon {
			results = append(results, c)
		}
	}
	return results
}

// GetComponentsByStatus returns components filtered by status
func (summary *ScanSummary) GetComponentsByStatus(status EOLStatus) []ComponentResult {
	var results []ComponentResult
	for _, c := range summary.Components {
		if c.Status == status {
			results = append(results, c)
		}
	}
	return results
}

// HasEOLComponents returns true if there are any EOL or EOL soon components
func (summary *ScanSummary) HasEOLComponents() bool {
	return summary.EOLComponents > 0 || summary.EOLSoonComponents > 0
}
