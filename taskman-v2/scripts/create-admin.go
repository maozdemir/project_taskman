package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	log.Println("🚀 TaskMan Admin User Creation Script")
	log.Println("=======================================")

	// Get database URLs from environment
	userDBURL := os.Getenv("USER_DATABASE_URL")
	iamDBURL := os.Getenv("IAM_DATABASE_URL")

	if userDBURL == "" {
		log.Fatal("❌ USER_DATABASE_URL environment variable is required")
	}

	if iamDBURL == "" {
		log.Fatal("❌ IAM_DATABASE_URL environment variable is required")
	}

	// Connect to User Service database
	userDB, err := sql.Open("postgres", userDBURL)
	if err != nil {
		log.Fatalf("❌ Failed to connect to User database: %v", err)
	}
	defer userDB.Close()

	if err := userDB.Ping(); err != nil {
		log.Fatalf("❌ Failed to ping User database: %v", err)
	}

	log.Println("✅ Connected to User database")

	// Connect to IAM Admin database
	iamDB, err := sql.Open("postgres", iamDBURL)
	if err != nil {
		log.Fatalf("❌ Failed to connect to IAM database: %v", err)
	}
	defer iamDB.Close()

	if err := iamDB.Ping(); err != nil {
		log.Fatalf("❌ Failed to ping IAM database: %v", err)
	}

	log.Println("✅ Connected to IAM database")

	ctx := context.Background()

	// Admin user details
	companyName := getEnvOrDefault("ADMIN_COMPANY_NAME", "TaskMan Admin")
	companySlug := getEnvOrDefault("ADMIN_COMPANY_SLUG", "taskman-admin")
	adminEmail := getEnvOrDefault("ADMIN_EMAIL", "admin@taskman.local")
	adminUsername := getEnvOrDefault("ADMIN_USERNAME", "admin")
	adminPassword := getEnvOrDefault("ADMIN_PASSWORD", "Admin123!@#")
	adminFirstName := getEnvOrDefault("ADMIN_FIRST_NAME", "Admin")
	adminLastName := getEnvOrDefault("ADMIN_LAST_NAME", "User")

	log.Println("\n📋 Admin User Configuration:")
	log.Printf("   Company: %s (%s)", companyName, companySlug)
	log.Printf("   Email: %s", adminEmail)
	log.Printf("   Username: %s", adminUsername)
	log.Printf("   Password: %s", adminPassword)

	// Step 1: Create company
	log.Println("\n📦 Step 1: Creating company...")
	companyID := uuid.New().String()

	_, err = userDB.ExecContext(ctx, `
		INSERT INTO companies (id, name, slug, subscription_tier, max_users, is_active, settings, created_at, updated_at)
		VALUES ($1, $2, $3, 'enterprise', 100, true, '{}'::jsonb, $4, $5)
		ON CONFLICT (slug) DO NOTHING
	`, companyID, companyName, companySlug, time.Now(), time.Now())

	if err != nil {
		log.Fatalf("❌ Failed to create company: %v", err)
	}

	// Check if company was created or already exists
	var existingCompanyID string
	err = userDB.QueryRowContext(ctx, `SELECT id FROM companies WHERE slug = $1`, companySlug).Scan(&existingCompanyID)
	if err != nil {
		log.Fatalf("❌ Failed to verify company: %v", err)
	}

	if existingCompanyID != companyID {
		companyID = existingCompanyID
		log.Printf("⚠️  Company already exists with ID: %s", companyID)
	} else {
		log.Printf("✅ Company created with ID: %s", companyID)
	}

	// Step 2: Create admin user
	log.Println("\n👤 Step 2: Creating admin user...")

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("❌ Failed to hash password: %v", err)
	}

	userID := uuid.New().String()

	_, err = userDB.ExecContext(ctx, `
		INSERT INTO users (id, company_id, email, username, password_hash, first_name, last_name,
		                   is_active, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, true, true, $8, $9)
		ON CONFLICT (company_id, email) DO NOTHING
	`, userID, companyID, adminEmail, adminUsername, string(passwordHash),
		adminFirstName, adminLastName, time.Now(), time.Now())

	if err != nil {
		log.Fatalf("❌ Failed to create admin user: %v", err)
	}

	// Check if user was created or already exists
	var existingUserID string
	err = userDB.QueryRowContext(ctx, `SELECT id FROM users WHERE company_id = $1 AND email = $2`,
		companyID, adminEmail).Scan(&existingUserID)
	if err != nil {
		log.Fatalf("❌ Failed to verify user: %v", err)
	}

	if existingUserID != userID {
		userID = existingUserID
		log.Printf("⚠️  User already exists with ID: %s", userID)
	} else {
		log.Printf("✅ Admin user created with ID: %s", userID)
	}

	// Step 3: Initialize system roles
	log.Println("\n🔐 Step 3: Creating system roles...")

	// Create admin role
	adminRoleID := uuid.New().String()
	_, err = iamDB.ExecContext(ctx, `
		INSERT INTO roles (id, company_id, name, description, is_system_role, priority, permissions, created_at, updated_at)
		VALUES ($1, $2, 'admin', 'Administrator with all permissions', true, 100, '["*:*"]'::jsonb, $3, $4)
		ON CONFLICT (company_id, name) DO NOTHING
	`, adminRoleID, companyID, time.Now(), time.Now())

	if err != nil {
		log.Fatalf("❌ Failed to create admin role: %v", err)
	}

	// Get admin role ID (in case it already existed)
	err = iamDB.QueryRowContext(ctx, `SELECT id FROM roles WHERE company_id = $1 AND name = 'admin'`,
		companyID).Scan(&adminRoleID)
	if err != nil {
		log.Fatalf("❌ Failed to get admin role: %v", err)
	}

	log.Printf("✅ Admin role ready with ID: %s", adminRoleID)

	// Create user role (default for new users)
	userRoleID := uuid.New().String()
	_, err = iamDB.ExecContext(ctx, `
		INSERT INTO roles (id, company_id, name, description, is_system_role, priority, permissions, created_at, updated_at)
		VALUES ($1, $2, 'user', 'Standard user with basic permissions', true, 0,
		        '["tasks:read:own", "tasks:create", "tasks:update:own", "tasks:delete:own"]'::jsonb, $3, $4)
		ON CONFLICT (company_id, name) DO NOTHING
	`, userRoleID, companyID, time.Now(), time.Now())

	if err != nil {
		log.Fatalf("❌ Failed to create user role: %v", err)
	}

	log.Printf("✅ User role ready")

	// Step 4: Assign admin role to admin user
	log.Println("\n🎯 Step 4: Assigning admin role...")

	userRoleAssignID := uuid.New().String()
	_, err = iamDB.ExecContext(ctx, `
		INSERT INTO user_roles (id, user_id, role_id, company_id, assigned_by, assigned_at)
		VALUES ($1, $2, $3, $4, $2, $5)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userRoleAssignID, userID, adminRoleID, companyID, time.Now())

	if err != nil {
		log.Fatalf("❌ Failed to assign admin role: %v", err)
	}

	log.Printf("✅ Admin role assigned to user")

	// Success summary
	log.Println("\n==================================================")
	log.Println("✅ Admin user creation completed successfully!")
	log.Println("==================================================")
	log.Println("\n📝 Login Credentials:")
	log.Printf("   Email:    %s", adminEmail)
	log.Printf("   Password: %s", adminPassword)
	log.Println("\n🔗 Resource IDs:")
	log.Printf("   Company ID: %s", companyID)
	log.Printf("   User ID:    %s", userID)
	log.Printf("   Role ID:    %s", adminRoleID)
	log.Println("\n⚠️  IMPORTANT: Change the admin password after first login!")
	log.Println("")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}