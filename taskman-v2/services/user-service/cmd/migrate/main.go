package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	_ "github.com/lib/pq"
)

func main() {
	// Get database URL from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// Connect to database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("✅ Connected to database")

	// Create migrations table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT NOW()
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create migrations table: %v", err)
	}

	// Get migrations directory
	migrationsDir := "migrations"
	if len(os.Args) > 1 && os.Args[1] == "down" {
		runMigrationsDown(db, migrationsDir)
	} else {
		runMigrationsUp(db, migrationsDir)
	}
}

func runMigrationsUp(db *sql.DB, migrationsDir string) {
	// Get all .up.sql files
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		log.Fatalf("Failed to read migrations directory: %v", err)
	}

	sort.Strings(files)

	if len(files) == 0 {
		log.Println("⚠️  No migration files found")
		return
	}

	log.Printf("📦 Found %d migration file(s)\n", len(files))

	for _, file := range files {
		version := filepath.Base(file)
		version = version[:len(version)-len(".up.sql")]

		// Check if already applied
		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&exists)
		if err != nil {
			log.Fatalf("Failed to check migration status: %v", err)
		}

		if exists {
			log.Printf("⏭️  Skipping %s (already applied)", version)
			continue
		}

		// Read migration file
		content, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("Failed to read migration file %s: %v", file, err)
		}

		// Execute migration
		log.Printf("▶️  Applying migration: %s", version)
		_, err = db.Exec(string(content))
		if err != nil {
			log.Fatalf("Failed to execute migration %s: %v", version, err)
		}

		// Record migration
		_, err = db.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", version)
		if err != nil {
			log.Fatalf("Failed to record migration %s: %v", version, err)
		}

		log.Printf("✅ Applied migration: %s", version)
	}

	log.Println("\n🎉 All migrations applied successfully!")
}

func runMigrationsDown(db *sql.DB, migrationsDir string) {
	// Get last applied migration
	var version string
	err := db.QueryRow("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version)
	if err == sql.ErrNoRows {
		log.Println("⚠️  No migrations to rollback")
		return
	}
	if err != nil {
		log.Fatalf("Failed to get last migration: %v", err)
	}

	downFile := filepath.Join(migrationsDir, version+".down.sql")

	// Check if down migration exists
	if _, err := os.Stat(downFile); os.IsNotExist(err) {
		log.Fatalf("Down migration file not found: %s", downFile)
	}

	// Read down migration
	content, err := os.ReadFile(downFile)
	if err != nil {
		log.Fatalf("Failed to read down migration file: %v", err)
	}

	// Execute down migration
	log.Printf("🔄 Rolling back migration: %s", version)
	_, err = db.Exec(string(content))
	if err != nil {
		log.Fatalf("Failed to execute down migration: %v", err)
	}

	// Remove from migrations table
	_, err = db.Exec("DELETE FROM schema_migrations WHERE version = $1", version)
	if err != nil {
		log.Fatalf("Failed to remove migration record: %v", err)
	}

	log.Printf("✅ Rolled back migration: %s", version)
	fmt.Println("\n🎉 Migration rolled back successfully!")
}
