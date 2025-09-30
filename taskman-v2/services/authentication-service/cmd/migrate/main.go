package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func main() {
	// Get database URL from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://taskman:taskman_dev_password@localhost:5432/taskman?sslmode=disable"
	}

	// Connect to database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Connected to database successfully")

	// Run migrations
	if err := runMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Println("Migrations completed successfully!")
}

func runMigrations(db *sql.DB) error {
	migrations := []string{
		// Enable UUID extension
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,

		// Sessions table
		`CREATE TABLE IF NOT EXISTS sessions (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID NOT NULL,
			refresh_token VARCHAR(512) NOT NULL UNIQUE,
			ip_address INET,
			user_agent TEXT,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			is_active BOOLEAN DEFAULT TRUE
		);`,

		// Indexes for sessions
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active) WHERE is_active = TRUE;`,

		// Password resets table
		`CREATE TABLE IF NOT EXISTS password_resets (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID NOT NULL,
			token VARCHAR(512) NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL,
			used BOOLEAN DEFAULT FALSE,
			used_at TIMESTAMP,
			ip_address INET,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		// Indexes for password_resets
		`CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_expires_at ON password_resets(expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_unused ON password_resets(used) WHERE used = FALSE;`,

		// Login attempts tracking
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			email VARCHAR(255) NOT NULL,
			ip_address INET NOT NULL,
			success BOOLEAN DEFAULT FALSE,
			error_message TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		// Indexes for login_attempts
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email);`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_email_time ON login_attempts(email, created_at);`,

		// Function to update updated_at timestamp
		`CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = NOW();
			RETURN NEW;
		END;
		$$ language 'plpgsql';`,

		// Trigger to automatically update updated_at
		`DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;`,
		`CREATE TRIGGER update_sessions_updated_at
			BEFORE UPDATE ON sessions
			FOR EACH ROW
			EXECUTE FUNCTION update_updated_at_column();`,
	}

	for i, migration := range migrations {
		fmt.Printf("Running migration %d/%d...\n", i+1, len(migrations))
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}

	return nil
}