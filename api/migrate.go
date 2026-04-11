package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// allowedMigrationGaps lists migration prefix numbers that are intentionally
// absent. These were removed during consolidation and documented in AGENTS.md.
var allowedMigrationGaps = map[int]bool{
	56: true,
	57: true,
	58: true,
}

// MigrationRunner handles database schema migrations using SQL files.
// Tracks applied migrations in a schema_migrations table.
// Uses PostgreSQL advisory locks to prevent concurrent runs.
func runMigrations(command string, args []string) {
	// validate only needs files on disk, no DB connection required
	if command != "validate" && dbPool == nil {
		log.Fatal("Database not initialized")
	}

	switch command {
	case "up":
		migrateUp()
	case "version":
		migrateVersion()
	case "status":
		migrateStatus()
	case "validate":
		migrateValidate()
	default:
		fmt.Printf("Unknown migration command: %s\n", command)
		fmt.Println("Usage: migrate [up|version|status|validate]")
	}
}

func ensureMigrationTable() {
	_, err := dbPool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ DEFAULT NOW()
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create schema_migrations table: %v", err)
	}
}

func acquireMigrationLock() bool {
	var acquired bool
	err := dbPool.QueryRow(context.Background(),
		"SELECT pg_try_advisory_lock(42)",
	).Scan(&acquired)
	if err != nil {
		log.Printf("Warning: could not acquire advisory lock: %v", err)
		return false
	}
	return acquired
}

func releaseMigrationLock() {
	dbPool.Exec(context.Background(), "SELECT pg_advisory_unlock(42)")
}

func getAppliedMigrations() map[string]bool {
	ensureMigrationTable()
	rows, err := dbPool.Query(context.Background(),
		"SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		log.Fatalf("Failed to query migrations: %v", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		rows.Scan(&version)
		applied[version] = true
	}
	return applied
}

// parseMigrationPrefix extracts the integer prefix from a migration filename
// like "041_network_beaconing_skill.sql" → 41. Returns -1 if unparseable.
func parseMigrationPrefix(basename string) int {
	idx := strings.Index(basename, "_")
	if idx < 1 {
		return -1
	}
	n, err := strconv.Atoi(basename[:idx])
	if err != nil {
		return -1
	}
	return n
}

func getMigrationFiles() []string {
	// Look for migrations in ./migrations/ relative to working directory
	dirs := []string{"./migrations", "../migrations", "/app/migrations"}
	var migrationDir string
	for _, d := range dirs {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			migrationDir = d
			break
		}
	}
	if migrationDir == "" {
		log.Println("No migrations directory found")
		return nil
	}

	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		log.Fatalf("Failed to read migrations directory: %v", err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			files = append(files, filepath.Join(migrationDir, entry.Name()))
		}
	}

	// Sort by parsed NNN prefix (integer order), not lexicographic.
	// This ensures 009 < 010 < 100 regardless of zero-padding differences.
	sort.Slice(files, func(i, j int) bool {
		pi := parseMigrationPrefix(filepath.Base(files[i]))
		pj := parseMigrationPrefix(filepath.Base(files[j]))
		if pi != pj {
			return pi < pj
		}
		// Same prefix (shouldn't happen after validation): fall back to name
		return filepath.Base(files[i]) < filepath.Base(files[j])
	})
	return files
}

// validateMigrations parses NNN_ prefixes from all migration SQL files and
// checks for duplicate prefixes and unexpected gaps. Gaps listed in
// allowedMigrationGaps are silently skipped. Returns nil on success or an
// error describing every violation found.
func validateMigrations(files []string) error {
	if len(files) == 0 {
		return nil
	}

	// Parse prefix → filename mapping
	prefixMap := make(map[int][]string) // prefix -> list of filenames (detect dupes)
	var prefixes []int

	for _, file := range files {
		base := filepath.Base(file)
		idx := strings.Index(base, "_")
		if idx < 1 {
			return fmt.Errorf("migration file %q has no NNN_ prefix", base)
		}
		numStr := base[:idx]
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return fmt.Errorf("migration file %q has non-numeric prefix %q", base, numStr)
		}
		prefixMap[num] = append(prefixMap[num], base)
		prefixes = append(prefixes, num)
	}

	// Deduplicate prefix list for gap analysis
	seen := make(map[int]bool)
	var uniquePrefixes []int
	for _, p := range prefixes {
		if !seen[p] {
			seen[p] = true
			uniquePrefixes = append(uniquePrefixes, p)
		}
	}
	sort.Ints(uniquePrefixes)

	var errs []string

	// Check for duplicate prefixes
	for num, filenames := range prefixMap {
		if len(filenames) > 1 {
			errs = append(errs, fmt.Sprintf("duplicate migration prefix %03d: %s",
				num, strings.Join(filenames, ", ")))
		}
	}

	// Check for gaps (from first prefix to last, every number must be present or allowlisted)
	if len(uniquePrefixes) >= 2 {
		first := uniquePrefixes[0]
		last := uniquePrefixes[len(uniquePrefixes)-1]
		for n := first; n <= last; n++ {
			if !seen[n] && !allowedMigrationGaps[n] {
				errs = append(errs, fmt.Sprintf("unexpected gap: migration %03d is missing (add to allowedMigrationGaps if intentional)", n))
			}
		}
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("migration validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func migrateUp() {
	if !acquireMigrationLock() {
		log.Fatal("Another migration is in progress (advisory lock held)")
	}
	defer releaseMigrationLock()

	applied := getAppliedMigrations()
	files := getMigrationFiles()

	if err := validateMigrations(files); err != nil {
		log.Fatalf("Migration validation failed — aborting:\n%v", err)
	}

	pending := 0
	for _, file := range files {
		version := filepath.Base(file)
		if applied[version] {
			continue
		}

		log.Printf("Applying migration: %s", version)
		content, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("Failed to read %s: %v", file, err)
		}

		_, err = dbPool.Exec(context.Background(), string(content))
		if err != nil {
			log.Fatalf("Migration %s failed: %v", version, err)
		}

		_, err = dbPool.Exec(context.Background(),
			"INSERT INTO schema_migrations (version) VALUES ($1)", version)
		if err != nil {
			log.Fatalf("Failed to record migration %s: %v", version, err)
		}

		log.Printf("Applied: %s", version)
		pending++
	}

	if pending == 0 {
		log.Println("No pending migrations")
	} else {
		log.Printf("Applied %d migrations", pending)
	}
}

func migrateVersion() {
	applied := getAppliedMigrations()
	var latest string
	for v := range applied {
		if v > latest {
			latest = v
		}
	}
	if latest == "" {
		fmt.Println("No migrations applied")
	} else {
		fmt.Printf("Current version: %s (%d total applied)\n", latest, len(applied))
	}
}

func migrateStatus() {
	applied := getAppliedMigrations()
	files := getMigrationFiles()

	if err := validateMigrations(files); err != nil {
		log.Fatalf("Migration validation failed:\n%v", err)
	}

	fmt.Printf("%-45s %s\n", "MIGRATION", "STATUS")
	fmt.Println(strings.Repeat("-", 60))
	for _, file := range files {
		version := filepath.Base(file)
		status := "PENDING"
		if applied[version] {
			status = "APPLIED"
		}
		fmt.Printf("%-45s %s\n", version, status)
	}
	fmt.Printf("\nTotal: %d applied, %d pending\n",
		len(applied), len(files)-len(applied))
}

// migrateValidate runs prefix validation without requiring a database connection.
// It only needs the migration files on disk. Exits 0 on success, 1 on failure.
func migrateValidate() {
	files := getMigrationFiles()
	if err := validateMigrations(files); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Migration validation passed: %d files, no duplicate prefixes, no unexpected gaps\n", len(files))
}
