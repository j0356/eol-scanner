package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewEOLDatabaseManager tests database manager creation
func TestNewEOLDatabaseManager(t *testing.T) {
	// Create temp directory for test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	if manager.db == nil {
		t.Error("NewEOLDatabaseManager() db is nil")
	}
	if manager.dbPath != dbPath {
		t.Errorf("NewEOLDatabaseManager() dbPath = %q, want %q", manager.dbPath, dbPath)
	}
	if manager.api == nil {
		t.Error("NewEOLDatabaseManager() api is nil")
	}

	// Verify database file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}
}

// TestDatabaseClose tests the Close method
func TestDatabaseClose(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}

	err = manager.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Should be safe to call close on nil db
	manager.db = nil
	err = manager.Close()
	if err != nil {
		t.Errorf("Close() on nil db error = %v", err)
	}
}

// TestDefaultDBPath tests the DefaultDBPath function
func TestDefaultDBPath(t *testing.T) {
	path, err := DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath() error = %v", err)
	}

	if path == "" {
		t.Error("DefaultDBPath() returned empty path")
	}

	// Should contain the expected directory and file names
	if !filepath.IsAbs(path) {
		t.Error("DefaultDBPath() should return absolute path")
	}

	dir := filepath.Dir(path)
	if filepath.Base(dir) != DefaultDBDir {
		t.Errorf("DefaultDBPath() dir = %q, want to contain %q", dir, DefaultDBDir)
	}

	if filepath.Base(path) != DefaultDBFile {
		t.Errorf("DefaultDBPath() filename = %q, want %q", filepath.Base(path), DefaultDBFile)
	}
}

// TestNormalizePackageName tests the normalizePackageName function
func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no suffix",
			input: "nginx",
			want:  "nginx",
		},
		{
			name:  "dev suffix",
			input: "libssl-dev",
			want:  "libssl",
		},
		{
			name:  "devel suffix",
			input: "openssl-devel",
			want:  "openssl",
		},
		{
			name:  "libs suffix",
			input: "libpng-libs",
			want:  "libpng",
		},
		{
			name:  "common suffix",
			input: "postgresql-common",
			want:  "postgresql",
		},
		{
			name:  "bin suffix",
			input: "python3-bin",
			want:  "python3",
		},
		{
			name:  "tools suffix",
			input: "docker-tools",
			want:  "docker",
		},
		{
			name:  "utils suffix",
			input: "coreutils-utils",
			want:  "coreutils",
		},
		{
			name:  "only first suffix stripped",
			input: "lib-dev-utils",
			want:  "lib-dev",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "suffix-like in middle",
			input: "dev-tools-extra",
			want:  "dev-tools-extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePackageName(tt.input)
			if got != tt.want {
				t.Errorf("normalizePackageName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestUpsertCategory tests the UpsertCategory method
func TestUpsertCategory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Insert a new category
	id, err := manager.UpsertCategory("lang", "Programming Languages", 50)
	if err != nil {
		t.Fatalf("UpsertCategory() error = %v", err)
	}
	if id <= 0 {
		t.Errorf("UpsertCategory() id = %d, want > 0", id)
	}

	// Update the same category
	id2, err := manager.UpsertCategory("lang", "Programming Languages", 55)
	if err != nil {
		t.Fatalf("UpsertCategory() update error = %v", err)
	}
	if id2 != id {
		t.Errorf("UpsertCategory() update id = %d, want %d", id2, id)
	}
}

// TestUpsertProduct tests the UpsertProduct method
func TestUpsertProduct(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// First, create a category
	_, err = manager.UpsertCategory("lang", "Languages", 10)
	if err != nil {
		t.Fatalf("UpsertCategory() error = %v", err)
	}

	product := ProductData{
		Name:     "python",
		Category: "lang",
		Label:    "Python",
		Links:    map[string]string{"html": "https://python.org"},
		Aliases:  []string{"python3", "cpython"},
		Tags:     []string{"language", "scripting"},
	}

	id, err := manager.UpsertProduct(product)
	if err != nil {
		t.Fatalf("UpsertProduct() error = %v", err)
	}
	if id <= 0 {
		t.Errorf("UpsertProduct() id = %d, want > 0", id)
	}

	// Update the same product
	product.Label = "Python (Updated)"
	id2, err := manager.UpsertProduct(product)
	if err != nil {
		t.Fatalf("UpsertProduct() update error = %v", err)
	}
	if id2 != id {
		t.Errorf("UpsertProduct() update id = %d, want %d", id2, id)
	}
}

// TestUpsertCycle tests the UpsertCycle method
func TestUpsertCycle(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product first
	product := ProductData{Name: "python", Category: "lang"}
	productID, err := manager.UpsertProduct(product)
	if err != nil {
		t.Fatalf("UpsertProduct() error = %v", err)
	}

	isEol := false
	release := ReleaseData{
		Name:         "3.12",
		Label:        "Python 3.12",
		ReleaseDate:  "2023-10-02",
		IsEol:        &isEol,
		EolFrom:      "2028-10-31",
		IsLts:        false,
		IsMaintained: true,
		Latest:       "3.12.1",
	}

	changed, err := manager.UpsertCycle(productID, release)
	if err != nil {
		t.Fatalf("UpsertCycle() error = %v", err)
	}
	if !changed {
		t.Error("UpsertCycle() should return changed=true for new cycle")
	}

	// Upsert same data should return unchanged
	changed, err = manager.UpsertCycle(productID, release)
	if err != nil {
		t.Fatalf("UpsertCycle() second call error = %v", err)
	}
	if changed {
		t.Error("UpsertCycle() should return changed=false for unchanged data")
	}
}

// TestUpsertIdentifiers tests the UpsertIdentifiers method
func TestUpsertIdentifiers(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product first
	product := ProductData{Name: "python", Category: "lang"}
	productID, err := manager.UpsertProduct(product)
	if err != nil {
		t.Fatalf("UpsertProduct() error = %v", err)
	}

	identifiers := []Identifier{
		{Type: "purl", ID: "pkg:pypi/python"},
		{Type: "cpe", ID: "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"},
		{Type: "repology", ID: "python"},
		{Type: "", ID: "empty-type"},     // Should be skipped
		{Type: "empty-id", ID: ""},       // Should be skipped
	}

	count, err := manager.UpsertIdentifiers(productID, identifiers)
	if err != nil {
		t.Fatalf("UpsertIdentifiers() error = %v", err)
	}
	if count != 3 {
		t.Errorf("UpsertIdentifiers() count = %d, want 3", count)
	}
}

// TestGetProductCycles tests the GetProductCycles method
func TestGetProductCycles(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product and cycles
	product := ProductData{Name: "python", Category: "lang"}
	productID, _ := manager.UpsertProduct(product)

	isEol := true
	releases := []ReleaseData{
		{Name: "3.12", ReleaseDate: "2023-10-02", EolFrom: "2028-10-31", IsMaintained: true},
		{Name: "3.11", ReleaseDate: "2022-10-24", EolFrom: "2027-10-24", IsMaintained: true},
		{Name: "2.7", ReleaseDate: "2010-07-03", IsEol: &isEol, IsMaintained: false},
	}

	for _, r := range releases {
		manager.UpsertCycle(productID, r)
	}

	cycles, err := manager.GetProductCycles("python")
	if err != nil {
		t.Fatalf("GetProductCycles() error = %v", err)
	}

	if len(cycles) != 3 {
		t.Errorf("GetProductCycles() returned %d cycles, want 3", len(cycles))
	}
}

// TestGetProductCyclesNotFound tests GetProductCycles for non-existent product
func TestGetProductCyclesNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	cycles, err := manager.GetProductCycles("nonexistent")
	if err != nil {
		t.Fatalf("GetProductCycles() error = %v", err)
	}

	if len(cycles) != 0 {
		t.Errorf("GetProductCycles() returned %d cycles, want 0", len(cycles))
	}
}

// TestLookupByName tests the LookupByName method
func TestLookupByName(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product with aliases
	product := ProductData{
		Name:     "postgresql",
		Category: "database",
		Aliases:  []string{"postgres", "psql", "pg"},
	}
	productID, _ := manager.UpsertProduct(product)
	manager.UpsertIdentifiers(productID, []Identifier{
		{Type: "repology", ID: "postgresql"},
	})

	// Test exact name match
	found, cycles, err := manager.LookupByName("postgresql", "database")
	if err != nil {
		t.Fatalf("LookupByName() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByName() should find product by exact name")
	}

	// Test alias match
	found, cycles, err = manager.LookupByName("postgres", "database")
	if err != nil {
		t.Fatalf("LookupByName() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByName() should find product by alias")
	}

	// Test repology match
	found, cycles, err = manager.LookupByName("postgresql", "database")
	if err != nil {
		t.Fatalf("LookupByName() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByName() should find product by repology identifier")
	}

	// Test not found
	found, cycles, err = manager.LookupByName("nonexistent", "database")
	if err != nil {
		t.Fatalf("LookupByName() error = %v", err)
	}
	if found != nil {
		t.Error("LookupByName() should return nil for nonexistent product")
	}
	_ = cycles // Avoid unused variable warning
}

// TestLookupByPURL tests the LookupByPURL method
func TestLookupByPURL(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product with PURL identifier
	product := ProductData{Name: "django", Category: "framework"}
	productID, _ := manager.UpsertProduct(product)
	manager.UpsertIdentifiers(productID, []Identifier{
		{Type: "purl", ID: "pkg:pypi/django"},
	})

	// Test exact match
	found, cycles, identifiers, err := manager.LookupByPURL("pkg:pypi/django")
	if err != nil {
		t.Fatalf("LookupByPURL() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByPURL() should find product by exact PURL")
	}

	// Test partial match (with version)
	found, cycles, identifiers, err = manager.LookupByPURL("pkg:pypi/django@4.2.1")
	if err != nil {
		t.Fatalf("LookupByPURL() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByPURL() should find product by PURL with version")
	}

	// Test not found
	found, _, _, err = manager.LookupByPURL("pkg:pypi/nonexistent")
	if err != nil {
		t.Fatalf("LookupByPURL() error = %v", err)
	}
	if found != nil {
		t.Error("LookupByPURL() should return nil for nonexistent PURL")
	}
	_ = cycles
	_ = identifiers
}

// TestLookupByCPE tests the LookupByCPE method
func TestLookupByCPE(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product with CPE identifier
	product := ProductData{Name: "nginx", Category: "server-app"}
	productID, _ := manager.UpsertProduct(product)
	manager.UpsertIdentifiers(productID, []Identifier{
		{Type: "cpe", ID: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
	})

	// Test exact match
	found, cycles, err := manager.LookupByCPE("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("LookupByCPE() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByCPE() should find product by exact CPE")
	}

	// Test prefix match
	found, cycles, err = manager.LookupByCPE("cpe:2.3:a:nginx:nginx")
	if err != nil {
		t.Fatalf("LookupByCPE() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByCPE() should find product by CPE prefix")
	}

	// Test not found
	found, _, err = manager.LookupByCPE("cpe:2.3:a:nonexistent:nonexistent")
	if err != nil {
		t.Fatalf("LookupByCPE() error = %v", err)
	}
	if found != nil {
		t.Error("LookupByCPE() should return nil for nonexistent CPE")
	}
	_ = cycles
}

// TestLookupByPURLPrefix tests the LookupByPURLPrefix method
func TestLookupByPURLPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product with PURL identifier
	product := ProductData{Name: "express", Category: "framework"}
	productID, _ := manager.UpsertProduct(product)
	manager.UpsertIdentifiers(productID, []Identifier{
		{Type: "purl", ID: "pkg:npm/express"},
	})

	// Test matching PURL prefix
	found, cycles, err := manager.LookupByPURLPrefix("npm", "express")
	if err != nil {
		t.Fatalf("LookupByPURLPrefix() error = %v", err)
	}
	if found == nil {
		t.Error("LookupByPURLPrefix() should find product")
	}

	// Test non-matching type
	found, _, err = manager.LookupByPURLPrefix("pypi", "express")
	if err != nil {
		t.Fatalf("LookupByPURLPrefix() error = %v", err)
	}
	if found != nil {
		t.Error("LookupByPURLPrefix() should return nil for wrong type")
	}
	_ = cycles
}

// TestGetStats tests the GetStats method
func TestGetStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create some test data
	manager.UpsertCategory("lang", "Languages", 2)
	manager.UpsertCategory("framework", "Frameworks", 1)

	product1 := ProductData{Name: "python", Category: "lang"}
	productID1, _ := manager.UpsertProduct(product1)
	manager.UpsertIdentifiers(productID1, []Identifier{
		{Type: "purl", ID: "pkg:pypi/python"},
		{Type: "cpe", ID: "cpe:2.3:a:python:python"},
	})

	product2 := ProductData{Name: "go", Category: "lang"}
	manager.UpsertProduct(product2)

	stats, err := manager.GetStats()
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}

	if stats.TotalProducts != 2 {
		t.Errorf("GetStats().TotalProducts = %d, want 2", stats.TotalProducts)
	}
	if stats.TotalCategories < 2 {
		t.Errorf("GetStats().TotalCategories = %d, want >= 2", stats.TotalCategories)
	}
	if stats.TotalIdentifiers != 2 {
		t.Errorf("GetStats().TotalIdentifiers = %d, want 2", stats.TotalIdentifiers)
	}
	if stats.ProductsByCategory["lang"] != 2 {
		t.Errorf("GetStats().ProductsByCategory[lang] = %d, want 2", stats.ProductsByCategory["lang"])
	}
}

// TestGetProductsByCategory tests the GetProductsByCategory method
func TestGetProductsByCategory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create test data
	manager.UpsertCategory("database", "Databases", 2)

	product1 := ProductData{Name: "postgresql", Category: "database"}
	manager.UpsertProduct(product1)

	product2 := ProductData{Name: "mysql", Category: "database"}
	manager.UpsertProduct(product2)

	product3 := ProductData{Name: "python", Category: "lang"}
	manager.UpsertProduct(product3)

	products, err := manager.GetProductsByCategory("database")
	if err != nil {
		t.Fatalf("GetProductsByCategory() error = %v", err)
	}

	if len(products) != 2 {
		t.Errorf("GetProductsByCategory() returned %d products, want 2", len(products))
	}

	// Verify they are the right products
	names := make(map[string]bool)
	for _, p := range products {
		names[p.Name] = true
	}
	if !names["postgresql"] || !names["mysql"] {
		t.Error("GetProductsByCategory() missing expected products")
	}
}

// TestGetEOLProducts tests the GetEOLProducts method
func TestGetEOLProducts(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product with EOL and active cycles
	product := ProductData{Name: "python", Category: "lang"}
	productID, _ := manager.UpsertProduct(product)

	pastDate := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	futureDate := time.Now().AddDate(1, 0, 0).Format("2006-01-02")

	isEol := true
	releases := []ReleaseData{
		{Name: "2.7", EolFrom: pastDate, IsEol: &isEol},                  // Past EOL
		{Name: "3.12", EolFrom: futureDate, IsMaintained: true},          // Future EOL (active)
	}

	for _, r := range releases {
		manager.UpsertCycle(productID, r)
	}

	// Get EOL products (past only)
	eolProducts, err := manager.GetEOLProducts(false, nil)
	if err != nil {
		t.Fatalf("GetEOLProducts() error = %v", err)
	}

	if len(eolProducts) != 1 {
		t.Errorf("GetEOLProducts(false, nil) returned %d products, want 1", len(eolProducts))
	}

	// Get EOL products including future
	eolProducts, err = manager.GetEOLProducts(true, nil)
	if err != nil {
		t.Fatalf("GetEOLProducts(true, nil) error = %v", err)
	}

	if len(eolProducts) != 2 {
		t.Errorf("GetEOLProducts(true, nil) returned %d products, want 2", len(eolProducts))
	}
}

// TestGetProductIdentifiers tests the GetProductIdentifiers method
func TestGetProductIdentifiers(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create product with identifiers
	product := ProductData{Name: "nodejs", Category: "lang"}
	productID, _ := manager.UpsertProduct(product)

	identifiers := []Identifier{
		{Type: "purl", ID: "pkg:generic/node"},
		{Type: "cpe", ID: "cpe:2.3:a:nodejs:node.js"},
		{Type: "repology", ID: "nodejs"},
	}
	manager.UpsertIdentifiers(productID, identifiers)

	// Get identifiers
	result, err := manager.GetProductIdentifiers("nodejs")
	if err != nil {
		t.Fatalf("GetProductIdentifiers() error = %v", err)
	}

	if len(result) != 3 {
		t.Errorf("GetProductIdentifiers() returned %d identifiers, want 3", len(result))
	}
}

// TestNewEndOfLifeAPI tests API client creation
func TestNewEndOfLifeAPI(t *testing.T) {
	api := NewEndOfLifeAPI()

	if api == nil {
		t.Fatal("NewEndOfLifeAPI() returned nil")
	}
	if api.baseURL != BaseURLV1 {
		t.Errorf("NewEndOfLifeAPI().baseURL = %q, want %q", api.baseURL, BaseURLV1)
	}
	if api.timeout != DefaultTimeout {
		t.Errorf("NewEndOfLifeAPI().timeout = %v, want %v", api.timeout, DefaultTimeout)
	}
	if api.client == nil {
		t.Error("NewEndOfLifeAPI().client is nil")
	}
}

// TestDefaultCategories tests that default categories are defined
func TestDefaultCategories(t *testing.T) {
	if len(DefaultCategories) == 0 {
		t.Error("DefaultCategories should not be empty")
	}

	expectedCategories := []string{"framework", "lang", "os", "database", "server-app"}
	for _, expected := range expectedCategories {
		found := false
		for _, cat := range DefaultCategories {
			if cat == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultCategories missing %q", expected)
		}
	}
}

// TestComputeHash tests the computeHash function
func TestComputeHash(t *testing.T) {
	data1 := map[string]string{"key": "value1"}
	data2 := map[string]string{"key": "value2"}
	data3 := map[string]string{"key": "value1"}

	hash1 := computeHash(data1)
	hash2 := computeHash(data2)
	hash3 := computeHash(data3)

	if hash1 == "" {
		t.Error("computeHash() returned empty string")
	}

	if hash1 == hash2 {
		t.Error("computeHash() should return different hashes for different data")
	}

	if hash1 != hash3 {
		t.Error("computeHash() should return same hash for identical data")
	}
}

// TestFullSyncCancelContext tests that FullSync respects context cancellation
func TestFullSyncCancelContext(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	manager, err := NewEOLDatabaseManager(dbPath)
	if err != nil {
		t.Fatalf("NewEOLDatabaseManager() error = %v", err)
	}
	defer manager.Close()

	// Create an already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = manager.FullSync(ctx, []string{"lang"})
	if err == nil {
		t.Error("FullSync() should return error for cancelled context")
	}
}

// TestDatabaseConstants tests that constants are correctly defined
func TestDatabaseConstants(t *testing.T) {
	if DefaultDBDir == "" {
		t.Error("DefaultDBDir should not be empty")
	}
	if DefaultDBFile == "" {
		t.Error("DefaultDBFile should not be empty")
	}
	if BaseURLV1 == "" {
		t.Error("BaseURLV1 should not be empty")
	}
	if DefaultTimeout <= 0 {
		t.Error("DefaultTimeout should be positive")
	}
}
