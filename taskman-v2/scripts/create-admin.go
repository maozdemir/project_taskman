package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

func main() {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://taskman:taskman_dev_password@localhost:5432/taskman?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	fmt.Println("Connected to database successfully")

	// Admin user details
	email := "admin@alperozdemir.com"
	username := "admin"
	password := "Alper123!"
	firstName := "Admin"
	lastName := "User"

	// Check if user already exists
	var existingID string
	err = db.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&existingID)
	if err == nil {
		fmt.Printf("User with email %s already exists (ID: %s)\n", email, existingID)
		return
	}

	// Hash password using bcrypt
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	// Insert admin user
	query := `
		INSERT INTO users (email, username, password_hash, first_name, last_name, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
		RETURNING id
	`

	var userID string
	err = db.QueryRow(query, email, username, string(passwordHash), firstName, lastName).Scan(&userID)
	if err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}

	fmt.Printf("✅ Admin user created successfully!\n")
	fmt.Printf("   User ID: %s\n", userID)
	fmt.Printf("   Email: %s\n", email)
	fmt.Printf("   Username: %s\n", username)
	fmt.Printf("   Password: %s\n", password)

	// Check if roles table exists and create admin role
	var rolesExist bool
	err = db.QueryRow("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'roles')").Scan(&rolesExist)
	if err != nil || !rolesExist {
		fmt.Println("\nNote: Roles table not found. User created without role assignment.")
		return
	}

	// Try to create admin role if it doesn't exist
	var roleID string
	err = db.QueryRow("SELECT id FROM roles WHERE name = 'admin' LIMIT 1").Scan(&roleID)

	if err == sql.ErrNoRows {
		// Create admin role
		err = db.QueryRow(`
			INSERT INTO roles (name, description, created_at, updated_at)
			VALUES ('admin', 'Administrator role with full access', NOW(), NOW())
			RETURNING id
		`).Scan(&roleID)

		if err != nil {
			fmt.Printf("Warning: Could not create admin role: %v\n", err)
			return
		}
		fmt.Printf("✅ Admin role created with ID: %s\n", roleID)
	}

	// Assign admin role to user
	if roleID != "" {
		_, err = db.Exec(`
			INSERT INTO user_roles (user_id, role_id, created_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT DO NOTHING
		`, userID, roleID)

		if err != nil {
			fmt.Printf("Warning: Could not assign admin role: %v\n", err)
		} else {
			fmt.Printf("✅ Admin role assigned to user\n")
		}
	}

	fmt.Println("\n🎉 Admin user setup complete!")
}