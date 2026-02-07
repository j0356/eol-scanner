package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/j0356/eol-scanner/core/db"
	"github.com/spf13/cobra"
)

// Database command flags
var (
	syncCategories []string
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage the EOL database",
	Long: `Commands for managing the local EOL database.

The database stores end-of-life information from endoflife.date
and is used to check components during scans.`,
}

var dbSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync the EOL database from endoflife.date",
	Long: `Synchronize the local database with the latest data from endoflife.date API.

This command fetches all product and cycle information for the configured
categories and stores it locally for offline scanning.

Default categories: framework, lang, os, database, server-app

Examples:
  # Sync with default categories
  eol-scanner db sync

  # Sync specific categories
  eol-scanner db sync --categories lang,framework,database

  # Sync to custom database path
  eol-scanner db sync --db /path/to/eol.db`,
	RunE: runDBSync,
}

var dbStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show database statistics",
	Long: `Display statistics about the local EOL database.

Shows information including:
- Last sync time
- Number of products, cycles, and identifiers
- Categories synced
- EOL vs active cycles breakdown`,
	RunE: runDBStats,
}

var dbPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show the database file path",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := dbPath
		if path == "" {
			var err error
			path, err = db.DefaultDBPath()
			if err != nil {
				return err
			}
		}
		fmt.Println(path)
		return nil
	},
}

func init() {
	// Add flags to sync command
	dbSyncCmd.Flags().StringSliceVar(&syncCategories, "categories", nil,
		"Categories to sync (default: framework,lang,os,database,server-app)")

	// Add subcommands to db command
	dbCmd.AddCommand(dbSyncCmd)
	dbCmd.AddCommand(dbStatsCmd)
	dbCmd.AddCommand(dbPathCmd)

	// Add db command to root
	rootCmd.AddCommand(dbCmd)
}

func runDBSync(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Determine database path
	path := dbPath
	if path == "" {
		var err error
		path, err = db.DefaultDBPath()
		if err != nil {
			return fmt.Errorf("failed to get default DB path: %w", err)
		}
	}

	if verbose {
		fmt.Printf("Database path: %s\n", path)
	}

	// Create database manager
	manager, err := db.NewEOLDatabaseManager(path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer manager.Close()

	// Determine categories to sync
	categories := syncCategories
	if len(categories) == 0 {
		categories = db.DefaultCategories
	}

	fmt.Printf("Syncing EOL database...\n")
	fmt.Printf("Categories: %s\n", strings.Join(categories, ", "))

	// Perform sync
	result, err := manager.FullSync(ctx, categories)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	// Print results
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Sync completed in %s\n", result.Duration)
	fmt.Printf("  Products processed:    %d\n", result.ProductsProcessed)
	fmt.Printf("  Cycles processed:      %d\n", result.CyclesProcessed)
	fmt.Printf("  Identifiers processed: %d\n", result.IdentifiersProcessed)
	if result.Errors > 0 {
		fmt.Printf("  Errors:                %d\n", result.Errors)
	}

	return nil
}

func runDBStats(cmd *cobra.Command, args []string) error {
	// Determine database path
	path := dbPath
	if path == "" {
		var err error
		path, err = db.DefaultDBPath()
		if err != nil {
			return fmt.Errorf("failed to get default DB path: %w", err)
		}
	}

	// Create database manager
	manager, err := db.NewEOLDatabaseManager(path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer manager.Close()

	// Get stats
	stats, err := manager.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	// Print stats
	fmt.Printf("\nEOL Database Statistics\n")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Database Path: %s\n", path)
	fmt.Println()

	// Sync info
	if stats.LastFullSync.Valid && stats.LastFullSync.String != "" {
		fmt.Printf("Last Full Sync:    %s\n", stats.LastFullSync.String)
	} else {
		fmt.Printf("Last Full Sync:    Never\n")
	}
	if stats.LastUpdateCheck.Valid && stats.LastUpdateCheck.String != "" {
		fmt.Printf("Last Update Check: %s\n", stats.LastUpdateCheck.String)
	}
	fmt.Println()

	// Categories
	if len(stats.CategoriesSynced) > 0 {
		fmt.Printf("Categories Synced: %s\n", strings.Join(stats.CategoriesSynced, ", "))
	}
	fmt.Println()

	// Counts
	fmt.Printf("Total Categories:  %d\n", stats.TotalCategories)
	fmt.Printf("Total Products:    %d\n", stats.TotalProducts)
	fmt.Printf("Total Cycles:      %d\n", stats.TotalCycles)
	fmt.Printf("Total Identifiers: %d\n", stats.TotalIdentifiers)
	fmt.Println()

	// EOL breakdown
	fmt.Printf("EOL Cycles:        %d\n", stats.EOLCycles)
	fmt.Printf("Active Cycles:     %d\n", stats.ActiveCycles)
	fmt.Println()

	// Products by category
	if len(stats.ProductsByCategory) > 0 {
		fmt.Println("Products by Category:")
		for cat, count := range stats.ProductsByCategory {
			fmt.Printf("  %-20s %d\n", cat, count)
		}
		fmt.Println()
	}

	// Identifiers by type
	if len(stats.IdentifiersByType) > 0 {
		fmt.Println("Identifiers by Type:")
		for typ, count := range stats.IdentifiersByType {
			fmt.Printf("  %-20s %d\n", typ, count)
		}
	}

	return nil
}
