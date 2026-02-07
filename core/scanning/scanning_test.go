package scanning

import (
	"database/sql"
	"testing"
	"time"

	"github.com/j0356/eol-scanner/core/db"
)

// TestMatchesVersion tests the matchesVersion function
func TestMatchesVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		cycle   string
		want    bool
	}{
		{
			name:    "exact match",
			version: "3.9",
			cycle:   "3.9",
			want:    true,
		},
		{
			name:    "version with patch matches cycle",
			version: "3.9.1",
			cycle:   "3.9",
			want:    true,
		},
		{
			name:    "version with dash suffix matches cycle",
			version: "3.9-alpine",
			cycle:   "3.9",
			want:    true,
		},
		{
			name:    "version with multiple patches matches cycle",
			version: "3.9.10.2",
			cycle:   "3.9",
			want:    true,
		},
		{
			name:    "version does not match different cycle",
			version: "3.10.1",
			cycle:   "3.9",
			want:    false,
		},
		{
			name:    "partial match should fail",
			version: "3.91",
			cycle:   "3.9",
			want:    false,
		},
		{
			name:    "major version only",
			version: "22",
			cycle:   "22",
			want:    true,
		},
		{
			name:    "version with build metadata",
			version: "1.21.0",
			cycle:   "1.21",
			want:    true,
		},
		{
			name:    "empty version",
			version: "",
			cycle:   "3.9",
			want:    false,
		},
		{
			name:    "empty cycle",
			version: "3.9.1",
			cycle:   "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesVersion(tt.version, tt.cycle)
			if got != tt.want {
				t.Errorf("matchesVersion(%q, %q) = %v, want %v", tt.version, tt.cycle, got, tt.want)
			}
		})
	}
}

// TestMatchesMajorVersion tests the matchesMajorVersion function
func TestMatchesMajorVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		cycle   string
		want    bool
	}{
		{
			name:    "same major version",
			version: "3.9.1",
			cycle:   "3.8",
			want:    true,
		},
		{
			name:    "different major versions",
			version: "4.0.0",
			cycle:   "3.9",
			want:    false,
		},
		{
			name:    "version with v prefix",
			version: "v2.1.0",
			cycle:   "2.0",
			want:    true,
		},
		{
			name:    "single digit versions",
			version: "22",
			cycle:   "22",
			want:    true,
		},
		{
			name:    "version with dash - no match due to extraction behavior",
			version: "3-alpine",
			cycle:   "3",
			want:    false, // extractMajorVersion returns "3-alpine", not "3"
		},
		{
			name:    "empty version",
			version: "",
			cycle:   "3",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesMajorVersion(tt.version, tt.cycle)
			if got != tt.want {
				t.Errorf("matchesMajorVersion(%q, %q) = %v, want %v", tt.version, tt.cycle, got, tt.want)
			}
		})
	}
}

// TestExtractMajorVersion tests the extractMajorVersion function
func TestExtractMajorVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "semver format",
			version: "3.9.1",
			want:    "3",
		},
		{
			name:    "with v prefix",
			version: "v2.1.0",
			want:    "2",
		},
		{
			name:    "single number",
			version: "22",
			want:    "22",
		},
		{
			name:    "dash separator - splits on dot first",
			version: "3-alpine",
			want:    "3-alpine", // Implementation splits on "." first, which doesn't exist
		},
		{
			name:    "underscore separator - splits on dot first",
			version: "3_0_1",
			want:    "3_0_1", // Implementation splits on "." first, which doesn't exist
		},
		{
			name:    "empty string",
			version: "",
			want:    "",
		},
		{
			name:    "complex version",
			version: "2024.01.15",
			want:    "2024",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMajorVersion(tt.version)
			if got != tt.want {
				t.Errorf("extractMajorVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// TestMapDistroToProduct tests the mapDistroToProduct function
func TestMapDistroToProduct(t *testing.T) {
	tests := []struct {
		name     string
		distroID string
		want     string
	}{
		{
			name:     "debian",
			distroID: "debian",
			want:     "debian",
		},
		{
			name:     "ubuntu",
			distroID: "ubuntu",
			want:     "ubuntu",
		},
		{
			name:     "alpine",
			distroID: "alpine",
			want:     "alpine-linux",
		},
		{
			name:     "centos",
			distroID: "centos",
			want:     "centos",
		},
		{
			name:     "rhel",
			distroID: "rhel",
			want:     "rhel",
		},
		{
			name:     "amazon linux",
			distroID: "amzn",
			want:     "amazon-linux",
		},
		{
			name:     "amazon linux alt",
			distroID: "amazonlinux",
			want:     "amazon-linux",
		},
		{
			name:     "rocky linux",
			distroID: "rocky",
			want:     "rocky-linux",
		},
		{
			name:     "oracle linux",
			distroID: "ol",
			want:     "oracle-linux",
		},
		{
			name:     "uppercase distro",
			distroID: "DEBIAN",
			want:     "debian",
		},
		{
			name:     "unknown distro returns ID",
			distroID: "customos",
			want:     "customos",
		},
		{
			name:     "empty distro",
			distroID: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapDistroToProduct(tt.distroID)
			if got != tt.want {
				t.Errorf("mapDistroToProduct(%q) = %q, want %q", tt.distroID, got, tt.want)
			}
		})
	}
}

// TestGetPURLTypeFromPackageType tests the getPURLTypeFromPackageType function
func TestGetPURLTypeFromPackageType(t *testing.T) {
	tests := []struct {
		name    string
		pkgType string
		want    string
	}{
		{
			name:    "python package",
			pkgType: "python",
			want:    "pypi",
		},
		{
			name:    "ruby gem",
			pkgType: "gem",
			want:    "gem",
		},
		{
			name:    "npm package",
			pkgType: "npm",
			want:    "npm",
		},
		{
			name:    "go module",
			pkgType: "go-module",
			want:    "golang",
		},
		{
			name:    "rust cargo",
			pkgType: "cargo",
			want:    "cargo",
		},
		{
			name:    "java archive",
			pkgType: "java-archive",
			want:    "maven",
		},
		{
			name:    "nuget package",
			pkgType: "nuget",
			want:    "nuget",
		},
		{
			name:    "deb package",
			pkgType: "deb",
			want:    "deb",
		},
		{
			name:    "rpm package",
			pkgType: "rpm",
			want:    "rpm",
		},
		{
			name:    "apk package",
			pkgType: "apk",
			want:    "apk",
		},
		{
			name:    "unknown type",
			pkgType: "unknown",
			want:    "",
		},
		{
			name:    "empty type",
			pkgType: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPURLTypeFromPackageType(tt.pkgType)
			if got != tt.want {
				t.Errorf("getPURLTypeFromPackageType(%q) = %q, want %q", tt.pkgType, got, tt.want)
			}
		})
	}
}

// TestParseEOLDate tests the parseEOLDate function
func TestParseEOLDate(t *testing.T) {
	tests := []struct {
		name    string
		dateStr string
		wantErr bool
		wantDay int
	}{
		{
			name:    "simple date format",
			dateStr: "2024-12-31",
			wantErr: false,
			wantDay: 31,
		},
		{
			name:    "RFC3339 format",
			dateStr: "2024-12-31T00:00:00Z",
			wantErr: false,
			wantDay: 31,
		},
		{
			name:    "RFC3339 with timezone",
			dateStr: "2024-12-31T00:00:00+00:00",
			wantErr: false,
			wantDay: 31,
		},
		{
			name:    "invalid format",
			dateStr: "31-12-2024",
			wantErr: true,
		},
		{
			name:    "empty string",
			dateStr: "",
			wantErr: true,
		},
		{
			name:    "invalid date",
			dateStr: "not-a-date",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEOLDate(tt.dateStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseEOLDate(%q) error = %v, wantErr %v", tt.dateStr, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Day() != tt.wantDay {
				t.Errorf("parseEOLDate(%q).Day() = %d, want %d", tt.dateStr, got.Day(), tt.wantDay)
			}
		})
	}
}

// TestDefaultScannerConfig tests the DefaultScannerConfig function
func TestDefaultScannerConfig(t *testing.T) {
	config := DefaultScannerConfig()

	if config == nil {
		t.Fatal("DefaultScannerConfig() returned nil")
	}

	if config.DBMaxAge != DefaultDBMaxAge {
		t.Errorf("DBMaxAge = %v, want %v", config.DBMaxAge, DefaultDBMaxAge)
	}

	if config.ForwardLookupDays != DefaultForwardLookup {
		t.Errorf("ForwardLookupDays = %d, want %d", config.ForwardLookupDays, DefaultForwardLookup)
	}

	if !config.AutoUpdateDB {
		t.Error("AutoUpdateDB should be true by default")
	}

	if len(config.Categories) == 0 {
		t.Error("Categories should not be empty by default")
	}
}

// TestScanSummaryGetEOLComponents tests the GetEOLComponents method
func TestScanSummaryGetEOLComponents(t *testing.T) {
	summary := &ScanSummary{
		Components: []ComponentResult{
			{Name: "pkg1", Status: StatusEOL},
			{Name: "pkg2", Status: StatusActive},
			{Name: "pkg3", Status: StatusEOLSoon},
			{Name: "pkg4", Status: StatusUnknown},
			{Name: "pkg5", Status: StatusEOL},
		},
	}

	eolComponents := summary.GetEOLComponents()

	if len(eolComponents) != 3 {
		t.Errorf("GetEOLComponents() returned %d components, want 3", len(eolComponents))
	}

	// Check that only EOL and EOL Soon are returned
	for _, c := range eolComponents {
		if c.Status != StatusEOL && c.Status != StatusEOLSoon {
			t.Errorf("GetEOLComponents() returned component with status %s", c.Status)
		}
	}
}

// TestScanSummaryGetComponentsByStatus tests the GetComponentsByStatus method
func TestScanSummaryGetComponentsByStatus(t *testing.T) {
	summary := &ScanSummary{
		Components: []ComponentResult{
			{Name: "pkg1", Status: StatusEOL},
			{Name: "pkg2", Status: StatusActive},
			{Name: "pkg3", Status: StatusEOLSoon},
			{Name: "pkg4", Status: StatusActive},
			{Name: "pkg5", Status: StatusUnknown},
		},
	}

	tests := []struct {
		status    EOLStatus
		wantCount int
	}{
		{StatusEOL, 1},
		{StatusActive, 2},
		{StatusEOLSoon, 1},
		{StatusUnknown, 1},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			components := summary.GetComponentsByStatus(tt.status)
			if len(components) != tt.wantCount {
				t.Errorf("GetComponentsByStatus(%s) returned %d components, want %d", tt.status, len(components), tt.wantCount)
			}
		})
	}
}

// TestScanSummaryHasEOLComponents tests the HasEOLComponents method
func TestScanSummaryHasEOLComponents(t *testing.T) {
	tests := []struct {
		name              string
		eolComponents     int
		eolSoonComponents int
		want              bool
	}{
		{
			name:              "has EOL components",
			eolComponents:     1,
			eolSoonComponents: 0,
			want:              true,
		},
		{
			name:              "has EOL soon components",
			eolComponents:     0,
			eolSoonComponents: 1,
			want:              true,
		},
		{
			name:              "has both",
			eolComponents:     2,
			eolSoonComponents: 3,
			want:              true,
		},
		{
			name:              "has neither",
			eolComponents:     0,
			eolSoonComponents: 0,
			want:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := &ScanSummary{
				EOLComponents:     tt.eolComponents,
				EOLSoonComponents: tt.eolSoonComponents,
			}
			got := summary.HasEOLComponents()
			if got != tt.want {
				t.Errorf("HasEOLComponents() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEOLStatusConstants tests that EOL status constants are defined correctly
func TestEOLStatusConstants(t *testing.T) {
	if StatusActive != "active" {
		t.Errorf("StatusActive = %q, want %q", StatusActive, "active")
	}
	if StatusEOL != "eol" {
		t.Errorf("StatusEOL = %q, want %q", StatusEOL, "eol")
	}
	if StatusEOLSoon != "eol_soon" {
		t.Errorf("StatusEOLSoon = %q, want %q", StatusEOLSoon, "eol_soon")
	}
	if StatusUnknown != "unknown" {
		t.Errorf("StatusUnknown = %q, want %q", StatusUnknown, "unknown")
	}
}

// TestEvaluateEOLStatusWithBooleanEOL tests evaluateEOLStatus when EOL is boolean true
func TestEvaluateEOLStatusWithBooleanEOL(t *testing.T) {
	scanner := &Scanner{
		config: &ScannerConfig{
			ForwardLookupDays: 90,
		},
	}

	cycles := []db.Cycle{
		{
			Cycle:      "3.9",
			EOLBoolean: toNullInt64(1),
		},
	}

	result := ComponentResult{
		Name:    "python",
		Version: "3.9.1",
		Status:  StatusUnknown,
	}

	result = scanner.evaluateEOLStatus(result, cycles, "3.9.1")

	if result.Status != StatusEOL {
		t.Errorf("evaluateEOLStatus() status = %s, want %s", result.Status, StatusEOL)
	}
	if result.MatchedCycle != "3.9" {
		t.Errorf("evaluateEOLStatus() MatchedCycle = %s, want %s", result.MatchedCycle, "3.9")
	}
}

// TestEvaluateEOLStatusWithFutureEOL tests evaluateEOLStatus when EOL is in the future
func TestEvaluateEOLStatusWithFutureEOL(t *testing.T) {
	scanner := &Scanner{
		config: &ScannerConfig{
			ForwardLookupDays: 90,
		},
	}

	// Set EOL date far in the future
	futureDate := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	cycles := []db.Cycle{
		{
			Cycle: "3.12",
			EOL:   toNullString(futureDate),
		},
	}

	result := ComponentResult{
		Name:    "python",
		Version: "3.12.1",
		Status:  StatusUnknown,
	}

	result = scanner.evaluateEOLStatus(result, cycles, "3.12.1")

	if result.Status != StatusActive {
		t.Errorf("evaluateEOLStatus() status = %s, want %s", result.Status, StatusActive)
	}
	if result.EOLDate != futureDate {
		t.Errorf("evaluateEOLStatus() EOLDate = %s, want %s", result.EOLDate, futureDate)
	}
	if result.DaysUntilEOL == nil {
		t.Error("evaluateEOLStatus() DaysUntilEOL should not be nil")
	}
}

// TestEvaluateEOLStatusWithEOLSoon tests evaluateEOLStatus when EOL is within forward lookup window
func TestEvaluateEOLStatusWithEOLSoon(t *testing.T) {
	scanner := &Scanner{
		config: &ScannerConfig{
			ForwardLookupDays: 90,
		},
	}

	// Set EOL date 30 days from now (within 90-day window)
	soonDate := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	cycles := []db.Cycle{
		{
			Cycle: "3.9",
			EOL:   toNullString(soonDate),
		},
	}

	result := ComponentResult{
		Name:    "python",
		Version: "3.9.1",
		Status:  StatusUnknown,
	}

	result = scanner.evaluateEOLStatus(result, cycles, "3.9.1")

	if result.Status != StatusEOLSoon {
		t.Errorf("evaluateEOLStatus() status = %s, want %s", result.Status, StatusEOLSoon)
	}
	if result.DaysUntilEOL == nil {
		t.Error("evaluateEOLStatus() DaysUntilEOL should not be nil")
	} else if *result.DaysUntilEOL < 25 || *result.DaysUntilEOL > 35 {
		t.Errorf("evaluateEOLStatus() DaysUntilEOL = %d, want around 30", *result.DaysUntilEOL)
	}
}

// TestEvaluateEOLStatusWithPastEOL tests evaluateEOLStatus when EOL is in the past
func TestEvaluateEOLStatusWithPastEOL(t *testing.T) {
	scanner := &Scanner{
		config: &ScannerConfig{
			ForwardLookupDays: 90,
		},
	}

	// Set EOL date in the past
	pastDate := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	cycles := []db.Cycle{
		{
			Cycle: "2.7",
			EOL:   toNullString(pastDate),
		},
	}

	result := ComponentResult{
		Name:    "python",
		Version: "2.7.18",
		Status:  StatusUnknown,
	}

	result = scanner.evaluateEOLStatus(result, cycles, "2.7.18")

	if result.Status != StatusEOL {
		t.Errorf("evaluateEOLStatus() status = %s, want %s", result.Status, StatusEOL)
	}
}

// TestEvaluateEOLStatusWithEmptyCycles tests evaluateEOLStatus with no cycles
func TestEvaluateEOLStatusWithEmptyCycles(t *testing.T) {
	scanner := &Scanner{
		config: &ScannerConfig{
			ForwardLookupDays: 90,
		},
	}

	result := ComponentResult{
		Name:    "unknown-pkg",
		Version: "1.0.0",
		Status:  StatusUnknown,
	}

	result = scanner.evaluateEOLStatus(result, []db.Cycle{}, "1.0.0")

	if result.Status != StatusUnknown {
		t.Errorf("evaluateEOLStatus() status = %s, want %s", result.Status, StatusUnknown)
	}
}

// TestEvaluateEOLStatusWithLTS tests that LTS flag is properly set
func TestEvaluateEOLStatusWithLTS(t *testing.T) {
	scanner := &Scanner{
		config: &ScannerConfig{
			ForwardLookupDays: 90,
		},
	}

	futureDate := time.Now().AddDate(2, 0, 0).Format("2006-01-02")
	cycles := []db.Cycle{
		{
			Cycle: "22.04",
			LTS:   1,
			EOL:   toNullString(futureDate),
		},
	}

	result := ComponentResult{
		Name:    "ubuntu",
		Version: "22.04",
		Status:  StatusUnknown,
	}

	result = scanner.evaluateEOLStatus(result, cycles, "22.04")

	if !result.IsLTS {
		t.Error("evaluateEOLStatus() IsLTS should be true")
	}
}

// TestNewScannerWithNilConfig tests NewScanner with nil config
func TestNewScannerWithNilConfig(t *testing.T) {
	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner(nil) returned error: %v", err)
	}
	if scanner == nil {
		t.Fatal("NewScanner(nil) returned nil scanner")
	}
	if scanner.config == nil {
		t.Error("NewScanner(nil) should create default config")
	}
	if scanner.config.ForwardLookupDays != DefaultForwardLookup {
		t.Errorf("Default ForwardLookupDays = %d, want %d", scanner.config.ForwardLookupDays, DefaultForwardLookup)
	}
}

// TestNewScannerWithCustomConfig tests NewScanner with custom config
func TestNewScannerWithCustomConfig(t *testing.T) {
	config := &ScannerConfig{
		ForwardLookupDays: 180,
		AutoUpdateDB:      false,
	}

	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner() returned error: %v", err)
	}
	if scanner.config.ForwardLookupDays != 180 {
		t.Errorf("ForwardLookupDays = %d, want 180", scanner.config.ForwardLookupDays)
	}
	if scanner.config.AutoUpdateDB {
		t.Error("AutoUpdateDB should be false")
	}
}

// TestScannerClose tests the Close method
func TestScannerClose(t *testing.T) {
	scanner, _ := NewScanner(nil)
	err := scanner.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Should be safe to call close multiple times
	err = scanner.Close()
	if err != nil {
		t.Errorf("Second Close() returned error: %v", err)
	}
}

// Helper functions for creating nullable types
func toNullInt64(v int64) sql.NullInt64 {
	return sql.NullInt64{Int64: v, Valid: true}
}

func toNullString(v string) sql.NullString {
	return sql.NullString{String: v, Valid: true}
}
