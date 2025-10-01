package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/idgen"
)

// Storage handles database operations
type Storage struct {
	db *database.DB
}

// New creates a new Storage instance
func New(db *database.DB) *Storage {
	return &Storage{db: db}
}

// Role represents a role entity
type Role struct {
	ID           string
	CompanyID    string
	Name         string
	Description  string
	IsSystemRole bool
	Priority     int
	Permissions  []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserRole represents a user-role assignment
type UserRole struct {
	ID         string
	UserID     string
	RoleID     string
	CompanyID  string
	AssignedBy string
	AssignedAt time.Time
	ExpiresAt  *time.Time
}

// Role operations

func (s *Storage) CreateRole(ctx context.Context, role *Role) error {
	query := `
		INSERT INTO roles (id, company_id, name, description, is_system_role, priority, permissions, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return errors.Internal("failed to marshal permissions")
	}

	_, err = s.db.ExecContext(ctx, query,
		role.ID,
		role.CompanyID,
		role.Name,
		role.Description,
		role.IsSystemRole,
		role.Priority,
		permissionsJSON,
		role.CreatedAt,
		role.UpdatedAt,
	)

	if err != nil {
		if database.IsUniqueViolation(err) {
			return errors.AlreadyExists(fmt.Sprintf("role '%s'", role.Name))
		}
		return errors.Internal("failed to create role")
	}

	return nil
}

func (s *Storage) GetRole(ctx context.Context, roleID, companyID string) (*Role, error) {
	query := `
		SELECT id, company_id, name, description, is_system_role, priority, permissions, created_at, updated_at
		FROM roles
		WHERE id = $1 AND company_id = $2
	`

	var role Role
	var permissionsJSON []byte

	err := s.db.QueryRowContext(ctx, query, roleID, companyID).Scan(
		&role.ID,
		&role.CompanyID,
		&role.Name,
		&role.Description,
		&role.IsSystemRole,
		&role.Priority,
		&permissionsJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound(fmt.Sprintf("role with id %s", roleID))
	}
	if err != nil {
		return nil, errors.Internal("failed to get role")
	}

	if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
		return nil, errors.Internal("failed to unmarshal permissions")
	}

	return &role, nil
}

func (s *Storage) GetRoleByName(ctx context.Context, name, companyID string) (*Role, error) {
	query := `
		SELECT id, company_id, name, description, is_system_role, priority, permissions, created_at, updated_at
		FROM roles
		WHERE name = $1 AND company_id = $2
	`

	var role Role
	var permissionsJSON []byte

	err := s.db.QueryRowContext(ctx, query, name, companyID).Scan(
		&role.ID,
		&role.CompanyID,
		&role.Name,
		&role.Description,
		&role.IsSystemRole,
		&role.Priority,
		&permissionsJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound(fmt.Sprintf("role '%s'", name))
	}
	if err != nil {
		return nil, errors.Internal("failed to get role by name")
	}

	if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
		return nil, errors.Internal("failed to unmarshal permissions")
	}

	return &role, nil
}

func (s *Storage) UpdateRole(ctx context.Context, role *Role) error {
	query := `
		UPDATE roles
		SET name = $2, description = $3, priority = $4, permissions = $5, updated_at = $6
		WHERE id = $1 AND company_id = $7
	`

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return errors.Internal("failed to marshal permissions")
	}

	result, err := s.db.ExecContext(ctx, query,
		role.ID,
		role.Name,
		role.Description,
		role.Priority,
		permissionsJSON,
		time.Now(),
		role.CompanyID,
	)

	if err != nil {
		if database.IsUniqueViolation(err) {
			return errors.AlreadyExists(fmt.Sprintf("role '%s'", role.Name))
		}
		return errors.Internal("failed to update role")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("role with id %s", role.ID))
	}

	return nil
}

func (s *Storage) DeleteRole(ctx context.Context, roleID, companyID string) error {
	query := `DELETE FROM roles WHERE id = $1 AND company_id = $2`

	result, err := s.db.ExecContext(ctx, query, roleID, companyID)
	if err != nil {
		// Check if it's a system role deletion attempt (caught by trigger)
		if strings.Contains(err.Error(), "system role") {
			return errors.PermissionDenied("cannot delete system role")
		}
		return errors.Internal("failed to delete role")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("role with id %s", roleID))
	}

	return nil
}

func (s *Storage) ListRoles(ctx context.Context, companyID string, includeSystemRoles bool) ([]*Role, error) {
	query := `
		SELECT id, company_id, name, description, is_system_role, priority, permissions, created_at, updated_at
		FROM roles
		WHERE company_id = $1
	`
	if !includeSystemRoles {
		query += ` AND is_system_role = FALSE`
	}
	query += ` ORDER BY priority DESC, name ASC`

	rows, err := s.db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, errors.Internal("failed to list roles")
	}
	defer rows.Close()

	roles := make([]*Role, 0)
	for rows.Next() {
		var role Role
		var permissionsJSON []byte

		err := rows.Scan(
			&role.ID,
			&role.CompanyID,
			&role.Name,
			&role.Description,
			&role.IsSystemRole,
			&role.Priority,
			&permissionsJSON,
			&role.CreatedAt,
			&role.UpdatedAt,
		)

		if err != nil {
			return nil, errors.Internal("failed to scan role")
		}

		if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
			return nil, errors.Internal("failed to unmarshal permissions")
		}

		roles = append(roles, &role)
	}

	return roles, nil
}

// UserRole operations

func (s *Storage) AssignRole(ctx context.Context, userRole *UserRole) error {
	query := `
		INSERT INTO user_roles (id, user_id, role_id, company_id, assigned_by, assigned_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.db.ExecContext(ctx, query,
		userRole.ID,
		userRole.UserID,
		userRole.RoleID,
		userRole.CompanyID,
		userRole.AssignedBy,
		userRole.AssignedAt,
		userRole.ExpiresAt,
	)

	if err != nil {
		if database.IsUniqueViolation(err) {
			return errors.AlreadyExists(fmt.Sprintf("user_role %s:%s", userRole.UserID, userRole.RoleID))
		}
		return errors.Internal("failed to assign role")
	}

	return nil
}

func (s *Storage) RevokeRole(ctx context.Context, userID, roleID, companyID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND company_id = $3`

	result, err := s.db.ExecContext(ctx, query, userID, roleID, companyID)
	if err != nil {
		return errors.Internal("failed to revoke role")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("user_role %s:%s", userID, roleID))
	}

	return nil
}

func (s *Storage) GetUserRoles(ctx context.Context, userID, companyID string) ([]*Role, error) {
	query := `
		SELECT r.id, r.company_id, r.name, r.description, r.is_system_role, r.priority, r.permissions, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.company_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		ORDER BY r.priority DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID, companyID)
	if err != nil {
		return nil, errors.Internal("failed to get user roles")
	}
	defer rows.Close()

	roles := make([]*Role, 0)
	for rows.Next() {
		var role Role
		var permissionsJSON []byte

		err := rows.Scan(
			&role.ID,
			&role.CompanyID,
			&role.Name,
			&role.Description,
			&role.IsSystemRole,
			&role.Priority,
			&permissionsJSON,
			&role.CreatedAt,
			&role.UpdatedAt,
		)

		if err != nil {
			return nil, errors.Internal("failed to scan role")
		}

		if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
			return nil, errors.Internal("failed to unmarshal permissions")
		}

		roles = append(roles, &role)
	}

	return roles, nil
}

func (s *Storage) ListUsersByRole(ctx context.Context, roleID, companyID string) ([]string, error) {
	query := `
		SELECT user_id
		FROM user_roles
		WHERE role_id = $1 AND company_id = $2
		  AND (expires_at IS NULL OR expires_at > NOW())
	`

	rows, err := s.db.QueryContext(ctx, query, roleID, companyID)
	if err != nil {
		return nil, errors.Internal("failed to list users by role")
	}
	defer rows.Close()

	userIDs := make([]string, 0)
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, errors.Internal("failed to scan user ID")
		}
		userIDs = append(userIDs, userID)
	}

	return userIDs, nil
}

// Helper functions for permissions

func (s *Storage) GetUserPermissions(ctx context.Context, userID, companyID string) ([]string, bool, error) {
	roles, err := s.GetUserRoles(ctx, userID, companyID)
	if err != nil {
		return nil, false, err
	}

	permissionsMap := make(map[string]bool)
	isAdmin := false

	for _, role := range roles {
		// Check if admin role
		if role.Priority >= 100 || containsPermission(role.Permissions, "*:*") {
			isAdmin = true
		}

		// Collect all permissions
		for _, perm := range role.Permissions {
			permissionsMap[perm] = true
		}
	}

	// Convert map to slice
	permissions := make([]string, 0, len(permissionsMap))
	for perm := range permissionsMap {
		permissions = append(permissions, perm)
	}

	return permissions, isAdmin, nil
}

func (s *Storage) HasPermission(ctx context.Context, userID, companyID, requiredPermission string) (bool, string) {
	permissions, isAdmin, err := s.GetUserPermissions(ctx, userID, companyID)
	if err != nil {
		return false, "failed to get user permissions"
	}

	// Admin bypass
	if isAdmin {
		return true, "Admin role grants all permissions"
	}

	// Check if user has the specific permission
	for _, perm := range permissions {
		if matchesPermission(perm, requiredPermission) {
			return true, ""
		}
	}

	return false, "Missing required permission: " + requiredPermission
}

// System role initialization

func (s *Storage) InitializeSystemRoles(ctx context.Context, companyID string) ([]*Role, error) {
	// Check if system roles already exist
	existingRoles, err := s.ListRoles(ctx, companyID, true)
	if err != nil {
		return nil, err
	}

	hasAdmin := false
	hasUser := false
	for _, role := range existingRoles {
		if role.Name == "admin" {
			hasAdmin = true
		}
		if role.Name == "user" {
			hasUser = true
		}
	}

	createdRoles := make([]*Role, 0)

	// Create admin role if it doesn't exist
	if !hasAdmin {
		adminRole := &Role{
			ID:           GenerateRoleID(),
			CompanyID:    companyID,
			Name:         "admin",
			Description:  "Administrator with all permissions",
			IsSystemRole: true,
			Priority:     100,
			Permissions:  []string{"*:*"},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := s.CreateRole(ctx, adminRole); err != nil {
			return nil, err
		}
		createdRoles = append(createdRoles, adminRole)
	}

	// Create user role if it doesn't exist
	if !hasUser {
		userRole := &Role{
			ID:           GenerateRoleID(),
			CompanyID:    companyID,
			Name:         "user",
			Description:  "Standard user with basic permissions",
			IsSystemRole: true,
			Priority:     0,
			Permissions: []string{
				"tasks:read:own",
				"tasks:create",
				"tasks:update:own",
				"tasks:delete:own",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if err := s.CreateRole(ctx, userRole); err != nil {
			return nil, err
		}
		createdRoles = append(createdRoles, userRole)
	}

	return createdRoles, nil
}

// Helper functions

func GenerateRoleID() string {
	return idgen.GenerateRoleID()
}

func GenerateUserRoleID() string {
	return idgen.GenerateUserRoleID()
}

func containsPermission(permissions []string, target string) bool {
	for _, perm := range permissions {
		if perm == target {
			return true
		}
	}
	return false
}

// matchesPermission checks if a permission matches the required permission
// Supports wildcards: "*:*" matches everything, "tasks:*" matches "tasks:create", etc.
func matchesPermission(permission, required string) bool {
	// Exact match
	if permission == required {
		return true
	}

	// Wildcard match
	if permission == "*:*" {
		return true
	}

	// Prefix wildcard (e.g., "tasks:*" matches "tasks:create")
	if strings.HasSuffix(permission, ":*") {
		prefix := strings.TrimSuffix(permission, ":*")
		if strings.HasPrefix(required, prefix+":") {
			return true
		}
	}

	return false
}
