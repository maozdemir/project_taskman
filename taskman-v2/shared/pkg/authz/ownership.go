package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/middleware"
)

// OwnershipValidator validates resource ownership for scope-based permissions
type OwnershipValidator struct {
	log *logger.Logger
}

// NewOwnershipValidator creates a new ownership validator
func NewOwnershipValidator(log *logger.Logger) *OwnershipValidator {
	return &OwnershipValidator{
		log: log,
	}
}

// ValidateOwnership checks if a permission has an :own scope and validates ownership
func (v *OwnershipValidator) ValidateOwnership(ctx context.Context, permission string, resourceOwnerID string) error {
	// Check if permission has :own scope
	if !strings.HasSuffix(permission, ":own") {
		// No ownership validation needed
		return nil
	}

	// Get user ID from context
	userID := middleware.GetUserID(ctx)
	if userID == "" {
		v.log.Warn("ownership validation failed: no user ID in context",
			"permission", permission)
		return errors.Unauthenticated("missing user context").ToGRPCError()
	}

	// SECURITY: Validate resource owner ID is not empty
	if resourceOwnerID == "" {
		v.log.Error("ownership validation failed: resource has no owner",
			"permission", permission,
			"user_id", userID)
		return errors.Internal("resource ownership data is missing").ToGRPCError()
	}

	// Check if user owns the resource
	if userID != resourceOwnerID {
		v.log.Warn("ownership validation failed",
			"permission", permission,
			"user_id", userID,
			"resource_owner_id", resourceOwnerID)
		return errors.PermissionDenied("you can only access your own resources").ToGRPCError()
	}

	v.log.Debug("ownership validation passed",
		"permission", permission,
		"user_id", userID)

	return nil
}

// CheckOwnership is a helper that checks both permission and ownership
func (v *OwnershipValidator) CheckOwnership(
	ctx context.Context,
	checker PermissionChecker,
	permission string,
	resourceOwnerID string,
) error {
	userID := middleware.GetUserID(ctx)
	companyID := middleware.GetCompanyID(ctx)

	if userID == "" || companyID == "" {
		return errors.Unauthenticated("missing authentication context").ToGRPCError()
	}

	// SECURITY: Validate resource owner ID
	if resourceOwnerID == "" {
		v.log.Error("ownership check failed: resource has no owner",
			"permission", permission,
			"user_id", userID,
			"company_id", companyID)
		return errors.Internal("resource ownership data is missing").ToGRPCError()
	}

	// First check if user has admin permission (wildcard bypass)
	allowed, reason, err := checker.HasPermission(ctx, userID, companyID, "*:*")
	if err != nil {
		return err
	}

	if allowed {
		// Admin has wildcard - no ownership check needed
		return nil
	}

	// Check if user has the general permission (without :own)
	basePermission := strings.TrimSuffix(permission, ":own")
	allowed, reason, err = checker.HasPermission(ctx, userID, companyID, basePermission)
	if err != nil {
		return err
	}

	if allowed {
		// User has general permission (e.g., tasks:update) - no ownership check needed
		return nil
	}

	// Check if user has the :own permission
	ownPermission := fmt.Sprintf("%s:own", basePermission)
	allowed, reason, err = checker.HasPermission(ctx, userID, companyID, ownPermission)
	if err != nil {
		return err
	}

	if !allowed {
		return errors.PermissionDenied(reason).ToGRPCError()
	}

	// User has :own permission - validate ownership
	return v.ValidateOwnership(ctx, ownPermission, resourceOwnerID)
}

// Resource represents a resource with ownership information
type Resource interface {
	GetOwnerID() string
	GetCompanyID() string
}

// ValidateResourceAccess validates both company isolation and ownership
func (v *OwnershipValidator) ValidateResourceAccess(
	ctx context.Context,
	checker PermissionChecker,
	permission string,
	resource Resource,
) error {
	// Validate company isolation
	if err := middleware.ValidateCompanyAccess(ctx, resource.GetCompanyID()); err != nil {
		return err
	}

	// Check ownership if permission has :own scope
	return v.CheckOwnership(ctx, checker, permission, resource.GetOwnerID())
}

// PermissionScope represents the scope of a permission
type PermissionScope string

const (
	// ScopeAll allows access to all resources
	ScopeAll PermissionScope = "all"
	// ScopeOwn allows access only to owned resources
	ScopeOwn PermissionScope = "own"
	// ScopeTeam allows access to team resources
	ScopeTeam PermissionScope = "team"
	// ScopeDepartment allows access to department resources
	ScopeDepartment PermissionScope = "department"
)

// ParsePermissionScope extracts the scope from a permission string
func ParsePermissionScope(permission string) (basePermission string, scope PermissionScope) {
	parts := strings.Split(permission, ":")
	if len(parts) < 2 {
		return permission, ScopeAll
	}

	lastPart := parts[len(parts)-1]
	switch lastPart {
	case "own":
		return strings.Join(parts[:len(parts)-1], ":"), ScopeOwn
	case "team":
		return strings.Join(parts[:len(parts)-1], ":"), ScopeTeam
	case "department":
		return strings.Join(parts[:len(parts)-1], ":"), ScopeDepartment
	default:
		return permission, ScopeAll
	}
}

// ShouldCheckOwnership returns true if the permission requires ownership validation
func ShouldCheckOwnership(permission string) bool {
	_, scope := ParsePermissionScope(permission)
	return scope == ScopeOwn || scope == ScopeTeam || scope == ScopeDepartment
}
