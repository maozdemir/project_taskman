package authz

import (
	"context"
	"fmt"
	"time"

	iamPb "github.com/taskman/v2/services/iam-admin-service/pkg/api/api"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// PermissionChecker interface defines permission checking operations
type PermissionChecker interface {
	HasPermission(ctx context.Context, userID, companyID, permission string) (bool, string, error)
	GetUserPermissions(ctx context.Context, userID, companyID string) ([]string, bool, error)
	InvalidateUserPermissions(ctx context.Context, userID, companyID string) error
}

// Checker implements permission checking with caching
type Checker struct {
	iamClient iamPb.IAMAdminServiceClient
	cache     *cache.Cache
	log       *logger.Logger
}

// Config holds checker configuration
type Config struct {
	IAMServiceAddr string
	Cache          *cache.Cache
	Logger         *logger.Logger
}

// NewChecker creates a new permission checker
func NewChecker(cfg *Config) (*Checker, error) {
	// Connect to IAM Admin Service
	conn, err := grpc.Dial(cfg.IAMServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IAM service: %w", err)
	}

	return &Checker{
		iamClient: iamPb.NewIAMAdminServiceClient(conn),
		cache:     cfg.Cache,
		log:       cfg.Logger,
	}, nil
}

// HasPermission checks if a user has a specific permission
func (c *Checker) HasPermission(ctx context.Context, userID, companyID, permission string) (bool, string, error) {
	// Validate inputs to prevent cache key manipulation
	if userID == "" || companyID == "" || permission == "" {
		return false, "invalid input parameters", fmt.Errorf("userID, companyID, and permission are required")
	}

	// Try cache first
	cacheKey := fmt.Sprintf("permission:%s:%s:%s", companyID, userID, permission)
	if c.cache != nil {
		// SECURITY FIX: Actually retrieve the cached value, don't assume true
		cachedResult, err := c.cache.Get(ctx, cacheKey)
		if err == nil && cachedResult != "" {
			if cachedResult == "true" {
				// Cache hit with positive permission
				c.log.Debug("permission cache hit (allowed)",
					"user_id", userID, "permission", permission)
				return true, "cached", nil
			} else if cachedResult == "false" {
				// Cache hit with negative permission
				c.log.Debug("permission cache hit (denied)",
					"user_id", userID, "permission", permission)
				return false, "cached denial", nil
			}
		}
		// Cache miss or error - continue to IAM service
	}

	// Cache miss - check with IAM service
	c.log.Debug("permission cache miss, checking with IAM service",
		"user_id", userID,
		"company_id", companyID,
		"permission", permission)

	resp, err := c.iamClient.HasPermission(ctx, &iamPb.HasPermissionRequest{
		UserId:     userID,
		CompanyId:  companyID,
		Permission: permission,
	})

	if err != nil {
		c.log.Error("failed to check permission",
			"user_id", userID,
			"permission", permission,
			"error", err)
		return false, "permission check failed", err
	}

	// Cache the result (both positive and negative)
	if c.cache != nil {
		// Cache for 5 minutes
		cacheValue := "false"
		if resp.Allowed {
			cacheValue = "true"
		}
		if err := c.cache.Set(ctx, cacheKey, cacheValue, 5*time.Minute); err != nil {
			c.log.Warn("failed to cache permission result", "error", err)
		}
	}

	return resp.Allowed, resp.Reason, nil
}

// GetUserPermissions retrieves all permissions for a user
func (c *Checker) GetUserPermissions(ctx context.Context, userID, companyID string) ([]string, bool, error) {
	resp, err := c.iamClient.GetUserPermissions(ctx, &iamPb.GetUserPermissionsRequest{
		UserId:    userID,
		CompanyId: companyID,
	})

	if err != nil {
		return nil, false, err
	}

	return resp.Permissions, resp.IsAdmin, nil
}

// InvalidateUserPermissions invalidates cached permissions for a user
func (c *Checker) InvalidateUserPermissions(ctx context.Context, userID, companyID string) error {
	if c.cache == nil {
		return nil
	}

	// Invalidate all permission caches for this user
	pattern := fmt.Sprintf("permission:%s:%s:*", companyID, userID)
	if err := c.cache.DeletePattern(ctx, pattern); err != nil {
		c.log.Warn("failed to invalidate user permission cache", "error", err)
		return err
	}

	return nil
}
