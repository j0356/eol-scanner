package db

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	// DefaultDBDir is the directory name for the EOL database in the home directory
	DefaultDBDir = "eol-db"
	// DefaultDBFile is the default database filename
	DefaultDBFile = "eol.db"
)

const (
	BaseURLV1      = "https://endoflife.date/api/v1"
	DefaultTimeout = 120 * time.Second
)

// DefaultCategories are the categories to track by default
var DefaultCategories = []string{
	"framework",
	"lang",
	"os",
	"database",
	"server-app",
}

// APIResponse represents the response from /api/v1/products/full
type APIResponse struct {
	Result []ProductData `json:"result"`
	Total  int           `json:"total"`
}

// ProductData represents a product from the API
type ProductData struct {
	Name           string            `json:"name"`
	Category       string            `json:"category"`
	Label          string            `json:"label"`
	Links          map[string]string `json:"links"`
	VersionCommand string            `json:"versionCommand"`
	Aliases        []string          `json:"aliases"`
	Tags           []string          `json:"tags"`
	Identifiers    []Identifier      `json:"identifiers"`
	Releases       []ReleaseData     `json:"releases"`
}

// Identifier represents a product identifier (cpe, purl, repology)
type Identifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ReleaseData represents a release/cycle from the API
type ReleaseData struct {
	Name        string      `json:"name"`
	Label       string      `json:"label"`
	Codename    string      `json:"codename"`
	ReleaseDate string      `json:"releaseDate"`
	IsEol       *bool       `json:"isEol"`
	EolFrom     string      `json:"eolFrom"`
	IsEoas      *bool       `json:"isEoas"`
	EoasFrom    string      `json:"eoasFrom"`
	IsLts       bool        `json:"isLts"`
	LtsFrom     string      `json:"ltsFrom"`
	Latest      interface{} `json:"latest"`
	IsMaintained bool       `json:"isMaintained"`
}

// LatestInfo represents the latest version info
type LatestInfo struct {
	Name string `json:"name"`
	Date string `json:"date"`
	Link string `json:"link"`
}

// EndOfLifeAPI is a client for the endoflife.date API
type EndOfLifeAPI struct {
	baseURL string
	timeout time.Duration
	client  *http.Client
}

// NewEndOfLifeAPI creates a new API client
func NewEndOfLifeAPI() *EndOfLifeAPI {
	return &EndOfLifeAPI{
		baseURL: BaseURLV1,
		timeout: DefaultTimeout,
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// GetAllProductsFull fetches all products from /api/v1/products/full
func (api *EndOfLifeAPI) GetAllProductsFull(ctx context.Context) ([]ProductData, error) {
	url := fmt.Sprintf("%s/products/full", api.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "EOL-Database-Manager/2.0")

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return apiResp.Result, nil
}

// EOLDatabaseManager manages the EOL SQLite database
type EOLDatabaseManager struct {
	db     *sql.DB
	dbPath string
	api    *EndOfLifeAPI
}

// DefaultDBPath returns the default database path in the user's home directory
// Creates the directory if it doesn't exist
func DefaultDBPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	dbDir := filepath.Join(homeDir, DefaultDBDir)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create database directory: %w", err)
	}

	return filepath.Join(dbDir, DefaultDBFile), nil
}

// NewEOLDatabaseManagerDefault creates a new database manager with the default path
// The database is stored at ~/eol-db/eol.db
func NewEOLDatabaseManagerDefault() (*EOLDatabaseManager, error) {
	dbPath, err := DefaultDBPath()
	if err != nil {
		return nil, err
	}
	return NewEOLDatabaseManager(dbPath)
}

// NewEOLDatabaseManager creates a new database manager
func NewEOLDatabaseManager(dbPath string) (*EOLDatabaseManager, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	manager := &EOLDatabaseManager{
		db:     db,
		dbPath: dbPath,
		api:    NewEndOfLifeAPI(),
	}

	if err := manager.initDatabase(); err != nil {
		db.Close()
		return nil, err
	}

	return manager, nil
}

// Close closes the database connection
func (m *EOLDatabaseManager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// initDatabase initializes the database schema
func (m *EOLDatabaseManager) initDatabase() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS categories (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			label TEXT,
			total_products INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS products (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			category_id INTEGER,
			category_name TEXT,
			label TEXT,
			link TEXT,
			version_command TEXT,
			aliases TEXT,
			tags TEXT,
			data_hash TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (category_id) REFERENCES categories(id)
		)`,
		`CREATE TABLE IF NOT EXISTS cycles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			product_id INTEGER NOT NULL,
			cycle TEXT NOT NULL,
			cycle_label TEXT,
			codename TEXT,
			release_date DATE,
			eol DATE,
			eol_boolean INTEGER,
			latest_version TEXT,
			latest_release_date DATE,
			lts INTEGER DEFAULT 0,
			lts_from DATE,
			support DATE,
			support_boolean INTEGER,
			discontinued DATE,
			discontinued_boolean INTEGER,
			extended_support DATE,
			extended_support_boolean INTEGER,
			is_maintained INTEGER DEFAULT 0,
			link TEXT,
			data_hash TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (product_id) REFERENCES products(id),
			UNIQUE(product_id, cycle)
		)`,
		`CREATE TABLE IF NOT EXISTS identifiers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			product_id INTEGER NOT NULL,
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (product_id) REFERENCES products(id),
			UNIQUE(product_id, identifier_type, identifier_value)
		)`,
		`CREATE TABLE IF NOT EXISTS sync_metadata (
			id INTEGER PRIMARY KEY,
			last_full_sync TIMESTAMP,
			last_update_check TIMESTAMP,
			categories_synced TEXT,
			products_count INTEGER DEFAULT 0,
			cycles_count INTEGER DEFAULT 0,
			identifiers_count INTEGER DEFAULT 0
		)`,
		`INSERT OR IGNORE INTO sync_metadata (id) VALUES (1)`,
		`CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_name)`,
		`CREATE INDEX IF NOT EXISTS idx_products_name ON products(name)`,
		`CREATE INDEX IF NOT EXISTS idx_cycles_product ON cycles(product_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cycles_eol ON cycles(eol)`,
		`CREATE INDEX IF NOT EXISTS idx_cycles_eol_bool ON cycles(eol_boolean)`,
		`CREATE INDEX IF NOT EXISTS idx_identifiers_product ON identifiers(product_id)`,
		`CREATE INDEX IF NOT EXISTS idx_identifiers_type ON identifiers(identifier_type)`,
		`CREATE INDEX IF NOT EXISTS idx_identifiers_value ON identifiers(identifier_value)`,
	}

	for _, query := range queries {
		if _, err := m.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// computeHash computes MD5 hash of data for change detection
func computeHash(data interface{}) string {
	jsonBytes, _ := json.Marshal(data)
	hash := md5.Sum(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// UpsertCategory inserts or updates a category
func (m *EOLDatabaseManager) UpsertCategory(name string, label string, total int) (int64, error) {
	_, err := m.db.Exec(`
		INSERT INTO categories (name, label, total_products, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET
			label = COALESCE(excluded.label, categories.label),
			total_products = excluded.total_products,
			updated_at = CURRENT_TIMESTAMP
	`, name, label, total)
	if err != nil {
		return 0, err
	}

	// Get the ID
	var id int64
	err = m.db.QueryRow("SELECT id FROM categories WHERE name = ?", name).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// UpsertProduct inserts or updates a product
func (m *EOLDatabaseManager) UpsertProduct(product ProductData) (int64, error) {
	var link string
	if product.Links != nil {
		link = product.Links["html"]
	}

	aliasesJSON, _ := json.Marshal(product.Aliases)
	tagsJSON, _ := json.Marshal(product.Tags)

	// Get category ID
	var categoryID sql.NullInt64
	err := m.db.QueryRow("SELECT id FROM categories WHERE name = ?", product.Category).Scan(&categoryID)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	_, err = m.db.Exec(`
		INSERT INTO products (name, category_id, category_name, label, link,
							  version_command, aliases, tags, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET
			category_id = COALESCE(excluded.category_id, products.category_id),
			category_name = COALESCE(excluded.category_name, products.category_name),
			label = COALESCE(excluded.label, products.label),
			link = COALESCE(excluded.link, products.link),
			version_command = COALESCE(excluded.version_command, products.version_command),
			aliases = excluded.aliases,
			tags = excluded.tags,
			updated_at = CURRENT_TIMESTAMP
	`, product.Name, categoryID, product.Category, product.Label, link,
		product.VersionCommand, string(aliasesJSON), string(tagsJSON))
	if err != nil {
		return 0, err
	}

	var id int64
	err = m.db.QueryRow("SELECT id FROM products WHERE name = ?", product.Name).Scan(&id)
	return id, err
}

// UpsertCycle inserts or updates a release cycle
func (m *EOLDatabaseManager) UpsertCycle(productID int64, release ReleaseData) (bool, error) {
	cycleName := release.Name
	dataHash := computeHash(release)

	// Check if exists and unchanged
	var existingHash sql.NullString
	err := m.db.QueryRow(`
		SELECT data_hash FROM cycles WHERE product_id = ? AND cycle = ?
	`, productID, cycleName).Scan(&existingHash)

	if err == nil && existingHash.Valid && existingHash.String == dataHash {
		return false, nil // No changes
	}

	// Parse EOL fields
	var eolDate sql.NullString
	var eolBool sql.NullInt64
	if release.EolFrom != "" {
		eolDate.String = release.EolFrom
		eolDate.Valid = true
	} else if release.IsEol != nil {
		if *release.IsEol {
			eolBool.Int64 = 1
		} else {
			eolBool.Int64 = 0
		}
		eolBool.Valid = true
	}

	// Parse support fields
	var supportDate sql.NullString
	var supportBool sql.NullInt64
	if release.EoasFrom != "" {
		supportDate.String = release.EoasFrom
		supportDate.Valid = true
	} else if release.IsEoas != nil {
		if *release.IsEoas {
			supportBool.Int64 = 1
		} else {
			supportBool.Int64 = 0
		}
		supportBool.Valid = true
	}

	// Handle LTS
	lts := 0
	if release.IsLts {
		lts = 1
	}

	// Handle latest version
	var latestVersion, latestDate, latestLink sql.NullString
	switch v := release.Latest.(type) {
	case string:
		latestVersion.String = v
		latestVersion.Valid = true
	case map[string]interface{}:
		if name, ok := v["name"].(string); ok {
			latestVersion.String = name
			latestVersion.Valid = true
		}
		if date, ok := v["date"].(string); ok {
			latestDate.String = date
			latestDate.Valid = true
		}
		if link, ok := v["link"].(string); ok {
			latestLink.String = link
			latestLink.Valid = true
		}
	}

	isMaintained := 0
	if release.IsMaintained {
		isMaintained = 1
	}

	_, err = m.db.Exec(`
		INSERT INTO cycles (
			product_id, cycle, cycle_label, codename, release_date,
			eol, eol_boolean, latest_version, latest_release_date,
			lts, lts_from, support, support_boolean,
			is_maintained, link, data_hash, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(product_id, cycle) DO UPDATE SET
			cycle_label = excluded.cycle_label,
			codename = excluded.codename,
			release_date = excluded.release_date,
			eol = excluded.eol,
			eol_boolean = excluded.eol_boolean,
			latest_version = excluded.latest_version,
			latest_release_date = excluded.latest_release_date,
			lts = excluded.lts,
			lts_from = excluded.lts_from,
			support = excluded.support,
			support_boolean = excluded.support_boolean,
			is_maintained = excluded.is_maintained,
			link = excluded.link,
			data_hash = excluded.data_hash,
			updated_at = CURRENT_TIMESTAMP
	`, productID, cycleName, release.Label, release.Codename, release.ReleaseDate,
		eolDate, eolBool, latestVersion, latestDate,
		lts, release.LtsFrom, supportDate, supportBool,
		isMaintained, latestLink, dataHash)

	return err == nil, err
}

// UpsertIdentifiers inserts or updates identifiers for a product
func (m *EOLDatabaseManager) UpsertIdentifiers(productID int64, identifiers []Identifier) (int, error) {
	count := 0
	for _, ident := range identifiers {
		if ident.Type == "" || ident.ID == "" {
			continue
		}

		_, err := m.db.Exec(`
			INSERT INTO identifiers (product_id, identifier_type, identifier_value, updated_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(product_id, identifier_type, identifier_value) DO UPDATE SET
				updated_at = CURRENT_TIMESTAMP
		`, productID, ident.Type, ident.ID)
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// SyncResult contains the results of a sync operation
type SyncResult struct {
	ProductsProcessed    int
	CyclesProcessed      int
	IdentifiersProcessed int
	Errors               int
	Duration             time.Duration
}

// FullSync performs a full sync from the API
func (m *EOLDatabaseManager) FullSync(ctx context.Context, categories []string) (*SyncResult, error) {
	if categories == nil {
		categories = DefaultCategories
	}

	startTime := time.Now()
	result := &SyncResult{}

	// Fetch all products
	allProducts, err := m.api.GetAllProductsFull(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch products: %w", err)
	}

	// Filter by categories
	categorySet := make(map[string]bool)
	for _, cat := range categories {
		categorySet[cat] = true
	}

	var filteredProducts []ProductData
	for _, p := range allProducts {
		if categorySet[p.Category] {
			filteredProducts = append(filteredProducts, p)
		}
	}

	// Count per category
	categoryCounts := make(map[string]int)
	for _, p := range filteredProducts {
		categoryCounts[p.Category]++
	}

	// Upsert categories
	for cat, count := range categoryCounts {
		if _, err := m.UpsertCategory(cat, "", count); err != nil {
			return nil, err
		}
	}

	// Process products
	for _, product := range filteredProducts {
		if product.Name == "" {
			continue
		}

		productID, err := m.UpsertProduct(product)
		if err != nil {
			result.Errors++
			continue
		}
		result.ProductsProcessed++

		// Upsert identifiers
		idCount, err := m.UpsertIdentifiers(productID, product.Identifiers)
		if err != nil {
			result.Errors++
		}
		result.IdentifiersProcessed += idCount

		// Upsert cycles
		for _, release := range product.Releases {
			changed, err := m.UpsertCycle(productID, release)
			if err != nil {
				result.Errors++
				continue
			}
			if changed {
				result.CyclesProcessed++
			}
		}
	}

	// Update sync metadata
	categoriesJSON, _ := json.Marshal(categories)
	_, err = m.db.Exec(`
		UPDATE sync_metadata SET
			last_full_sync = CURRENT_TIMESTAMP,
			last_update_check = CURRENT_TIMESTAMP,
			categories_synced = ?,
			products_count = (SELECT COUNT(*) FROM products),
			cycles_count = (SELECT COUNT(*) FROM cycles),
			identifiers_count = (SELECT COUNT(*) FROM identifiers)
		WHERE id = 1
	`, string(categoriesJSON))

	result.Duration = time.Since(startTime)
	return result, err
}

// Product represents a product from the database
type Product struct {
	ID             int64
	Name           string
	CategoryID     sql.NullInt64
	CategoryName   sql.NullString
	Label          sql.NullString
	Link           sql.NullString
	VersionCommand sql.NullString
	Aliases        sql.NullString
	Tags           sql.NullString
}

// Cycle represents a release cycle from the database
type Cycle struct {
	ID                int64
	ProductID         int64
	Cycle             string
	CycleLabel        sql.NullString
	Codename          sql.NullString
	ReleaseDate       sql.NullString
	EOL               sql.NullString
	EOLBoolean        sql.NullInt64
	LatestVersion     sql.NullString
	LatestReleaseDate sql.NullString
	LTS               int
	LTSFrom           sql.NullString
	Support           sql.NullString
	SupportBoolean    sql.NullInt64
	IsMaintained      int
}

// GetProductsByCategory returns products in a category
func (m *EOLDatabaseManager) GetProductsByCategory(category string) ([]Product, error) {
	rows, err := m.db.Query(`
		SELECT id, name, category_id, category_name, label, link, version_command, aliases, tags
		FROM products WHERE category_name = ?
		ORDER BY name
	`, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.CategoryID, &p.CategoryName,
			&p.Label, &p.Link, &p.VersionCommand, &p.Aliases, &p.Tags); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	return products, rows.Err()
}

// GetProductCycles returns all cycles for a product
func (m *EOLDatabaseManager) GetProductCycles(productName string) ([]Cycle, error) {
	rows, err := m.db.Query(`
		SELECT c.id, c.product_id, c.cycle, c.cycle_label, c.codename, c.release_date,
			   c.eol, c.eol_boolean, c.latest_version, c.latest_release_date,
			   c.lts, c.lts_from, c.support, c.support_boolean, c.is_maintained
		FROM cycles c
		JOIN products p ON c.product_id = p.id
		WHERE p.name = ?
		ORDER BY c.release_date DESC
	`, productName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cycles []Cycle
	for rows.Next() {
		var c Cycle
		if err := rows.Scan(&c.ID, &c.ProductID, &c.Cycle, &c.CycleLabel, &c.Codename,
			&c.ReleaseDate, &c.EOL, &c.EOLBoolean, &c.LatestVersion, &c.LatestReleaseDate,
			&c.LTS, &c.LTSFrom, &c.Support, &c.SupportBoolean, &c.IsMaintained); err != nil {
			return nil, err
		}
		cycles = append(cycles, c)
	}
	return cycles, rows.Err()
}

// EOLProduct represents an EOL product/cycle result
type EOLProduct struct {
	Name          string
	CategoryName  string
	Cycle         string
	EOL           sql.NullString
	LatestVersion sql.NullString
	LTS           int
}

// GetEOLProducts returns products/cycles that are EOL
func (m *EOLDatabaseManager) GetEOLProducts(includeFuture bool, daysAhead *int) ([]EOLProduct, error) {
	today := time.Now().Format("2006-01-02")

	var query string
	var args []interface{}

	if daysAhead != nil {
		cutoff := time.Now().AddDate(0, 0, *daysAhead).Format("2006-01-02")
		query = `
			SELECT p.name, p.category_name, c.cycle, c.eol, c.latest_version, c.lts
			FROM cycles c
			JOIN products p ON c.product_id = p.id
			WHERE (c.eol IS NOT NULL AND c.eol <= ?) OR c.eol_boolean = 1
			ORDER BY c.eol ASC
		`
		args = []interface{}{cutoff}
	} else if includeFuture {
		query = `
			SELECT p.name, p.category_name, c.cycle, c.eol, c.latest_version, c.lts
			FROM cycles c
			JOIN products p ON c.product_id = p.id
			WHERE c.eol IS NOT NULL OR c.eol_boolean = 1
			ORDER BY c.eol ASC
		`
	} else {
		query = `
			SELECT p.name, p.category_name, c.cycle, c.eol, c.latest_version, c.lts
			FROM cycles c
			JOIN products p ON c.product_id = p.id
			WHERE (c.eol IS NOT NULL AND c.eol <= ?) OR c.eol_boolean = 1
			ORDER BY c.eol DESC
		`
		args = []interface{}{today}
	}

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []EOLProduct
	for rows.Next() {
		var p EOLProduct
		if err := rows.Scan(&p.Name, &p.CategoryName, &p.Cycle, &p.EOL, &p.LatestVersion, &p.LTS); err != nil {
			return nil, err
		}
		results = append(results, p)
	}
	return results, rows.Err()
}

// ProductIdentifier represents an identifier from the database
type ProductIdentifier struct {
	Type  string
	Value string
}

// GetProductIdentifiers returns identifiers for a product
func (m *EOLDatabaseManager) GetProductIdentifiers(productName string) ([]ProductIdentifier, error) {
	rows, err := m.db.Query(`
		SELECT i.identifier_type, i.identifier_value
		FROM identifiers i
		JOIN products p ON i.product_id = p.id
		WHERE p.name = ?
		ORDER BY i.identifier_type
	`, productName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identifiers []ProductIdentifier
	for rows.Next() {
		var id ProductIdentifier
		if err := rows.Scan(&id.Type, &id.Value); err != nil {
			return nil, err
		}
		identifiers = append(identifiers, id)
	}
	return identifiers, rows.Err()
}

// LookupByPURL looks up a product by its PURL identifier
func (m *EOLDatabaseManager) LookupByPURL(purl string) (*Product, []Cycle, []ProductIdentifier, error) {
	var product Product
	err := m.db.QueryRow(`
		SELECT p.id, p.name, p.category_id, p.category_name, p.label, p.link, p.version_command, p.aliases, p.tags
		FROM products p
		JOIN identifiers i ON p.id = i.product_id
		WHERE i.identifier_type = 'purl' AND i.identifier_value = ?
	`, purl).Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
		&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)

	if err == sql.ErrNoRows {
		// Try partial match
		purlBase := purl
		for i := len(purl) - 1; i >= 0; i-- {
			if purl[i] == '@' {
				purlBase = purl[:i]
				break
			}
		}

		err = m.db.QueryRow(`
			SELECT p.id, p.name, p.category_id, p.category_name, p.label, p.link, p.version_command, p.aliases, p.tags
			FROM products p
			JOIN identifiers i ON p.id = i.product_id
			WHERE i.identifier_type = 'purl' AND i.identifier_value LIKE ?
		`, purlBase+"%").Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
			&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, err
	}

	cycles, err := m.GetProductCycles(product.Name)
	if err != nil {
		return nil, nil, nil, err
	}

	identifiers, err := m.GetProductIdentifiers(product.Name)
	if err != nil {
		return nil, nil, nil, err
	}

	return &product, cycles, identifiers, nil
}

// Stats represents database statistics
type Stats struct {
	LastFullSync      sql.NullString
	LastUpdateCheck   sql.NullString
	CategoriesSynced  []string
	TotalCategories   int
	TotalProducts     int
	TotalCycles       int
	TotalIdentifiers  int
	EOLCycles         int
	ActiveCycles      int
	IdentifiersByType map[string]int
	ProductsByCategory map[string]int
}

// LookupByCPE looks up a product by its CPE identifier
// Supports both CPE 2.2 (cpe:/a:vendor:product) and CPE 2.3 (cpe:2.3:a:vendor:product) formats
func (m *EOLDatabaseManager) LookupByCPE(cpeString string) (*Product, []Cycle, error) {
	var product Product

	// Try exact match first
	err := m.db.QueryRow(`
		SELECT p.id, p.name, p.category_id, p.category_name, p.label, p.link, p.version_command, p.aliases, p.tags
		FROM products p
		JOIN identifiers i ON p.id = i.product_id
		WHERE i.identifier_type = 'cpe' AND LOWER(i.identifier_value) = LOWER(?)
	`, cpeString).Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
		&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)

	if err == sql.ErrNoRows {
		// Try prefix match (CPE without version)
		// Remove version from CPE for matching: cpe:2.3:a:vendor:product:* -> cpe:2.3:a:vendor:product
		pattern := cpeString + "%"
		err = m.db.QueryRow(`
			SELECT p.id, p.name, p.category_id, p.category_name, p.label, p.link, p.version_command, p.aliases, p.tags
			FROM products p
			JOIN identifiers i ON p.id = i.product_id
			WHERE i.identifier_type = 'cpe' AND LOWER(i.identifier_value) LIKE LOWER(?)
		`, pattern).Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
			&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	cycles, err := m.GetProductCycles(product.Name)
	if err != nil {
		return nil, nil, err
	}

	return &product, cycles, nil
}

// LookupByPURLPrefix looks up a product by matching a PURL prefix pattern
// For example, pkg:pypi/django would match pkg:pypi/django in the database
func (m *EOLDatabaseManager) LookupByPURLPrefix(purlType, packageName string) (*Product, []Cycle, error) {
	var product Product

	// Construct a pattern to match: pkg:<type>/<name> or pkg:<type>/%40<scope>/<name>
	pattern := fmt.Sprintf("pkg:%s/%s%%", purlType, packageName)
	patternWithScope := fmt.Sprintf("pkg:%s/%%/%s%%", purlType, packageName)

	err := m.db.QueryRow(`
		SELECT p.id, p.name, p.category_id, p.category_name, p.label, p.link, p.version_command, p.aliases, p.tags
		FROM products p
		JOIN identifiers i ON p.id = i.product_id
		WHERE i.identifier_type = 'purl' AND (
			LOWER(i.identifier_value) LIKE LOWER(?) OR
			LOWER(i.identifier_value) LIKE LOWER(?)
		)
	`, pattern, patternWithScope).Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
		&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	cycles, err := m.GetProductCycles(product.Name)
	if err != nil {
		return nil, nil, err
	}

	return &product, cycles, nil
}

// LookupByName looks up a product by name, checking product name, aliases, and repology identifiers
func (m *EOLDatabaseManager) LookupByName(name string, pkgType string) (*Product, []Cycle, error) {
	var product Product

	// Normalize the name for matching
	normalizedName := normalizePackageName(name)

	// Try exact product name match first
	err := m.db.QueryRow(`
		SELECT id, name, category_id, category_name, label, link, version_command, aliases, tags
		FROM products WHERE LOWER(name) = LOWER(?)
	`, normalizedName).Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
		&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)

	if err == sql.ErrNoRows {
		// Try matching against aliases
		err = m.db.QueryRow(`
			SELECT id, name, category_id, category_name, label, link, version_command, aliases, tags
			FROM products WHERE aliases LIKE ?
		`, "%\""+normalizedName+"\"%").Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
			&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)
	}

	if err == sql.ErrNoRows {
		// Try matching via repology identifier
		err = m.db.QueryRow(`
			SELECT p.id, p.name, p.category_id, p.category_name, p.label, p.link, p.version_command, p.aliases, p.tags
			FROM products p
			JOIN identifiers i ON p.id = i.product_id
			WHERE i.identifier_type = 'repology' AND LOWER(i.identifier_value) = LOWER(?)
		`, normalizedName).Scan(&product.ID, &product.Name, &product.CategoryID, &product.CategoryName,
			&product.Label, &product.Link, &product.VersionCommand, &product.Aliases, &product.Tags)
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	cycles, err := m.GetProductCycles(product.Name)
	if err != nil {
		return nil, nil, err
	}

	return &product, cycles, nil
}

// normalizePackageName normalizes a package name for matching
func normalizePackageName(name string) string {
	// Common suffixes to strip for matching
	suffixes := []string{"-dev", "-devel", "-libs", "-common", "-bin", "-tools", "-utils"}
	result := name

	for _, suffix := range suffixes {
		if len(result) > len(suffix) && result[len(result)-len(suffix):] == suffix {
			result = result[:len(result)-len(suffix)]
			break
		}
	}

	return result
}

// GetStats returns database statistics
func (m *EOLDatabaseManager) GetStats() (*Stats, error) {
	stats := &Stats{
		IdentifiersByType:  make(map[string]int),
		ProductsByCategory: make(map[string]int),
	}

	// Sync metadata
	var categoriesJSON sql.NullString
	err := m.db.QueryRow(`
		SELECT last_full_sync, last_update_check, categories_synced
		FROM sync_metadata WHERE id = 1
	`).Scan(&stats.LastFullSync, &stats.LastUpdateCheck, &categoriesJSON)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if categoriesJSON.Valid {
		json.Unmarshal([]byte(categoriesJSON.String), &stats.CategoriesSynced)
	}

	// Counts
	m.db.QueryRow("SELECT COUNT(*) FROM categories").Scan(&stats.TotalCategories)
	m.db.QueryRow("SELECT COUNT(*) FROM products").Scan(&stats.TotalProducts)
	m.db.QueryRow("SELECT COUNT(*) FROM cycles").Scan(&stats.TotalCycles)
	m.db.QueryRow("SELECT COUNT(*) FROM identifiers").Scan(&stats.TotalIdentifiers)

	today := time.Now().Format("2006-01-02")
	m.db.QueryRow(`
		SELECT COUNT(*) FROM cycles
		WHERE (eol IS NOT NULL AND eol <= ?) OR eol_boolean = 1
	`, today).Scan(&stats.EOLCycles)

	m.db.QueryRow(`
		SELECT COUNT(*) FROM cycles
		WHERE eol IS NOT NULL AND eol > ?
	`, today).Scan(&stats.ActiveCycles)

	// Identifiers by type
	rows, _ := m.db.Query(`
		SELECT identifier_type, COUNT(*) FROM identifiers
		GROUP BY identifier_type
	`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var c int
			rows.Scan(&t, &c)
			stats.IdentifiersByType[t] = c
		}
	}

	// Products by category
	rows, _ = m.db.Query(`
		SELECT category_name, COUNT(*) FROM products
		WHERE category_name IS NOT NULL
		GROUP BY category_name
	`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cat string
			var c int
			rows.Scan(&cat, &c)
			stats.ProductsByCategory[cat] = c
		}
	}

	return stats, nil
}
