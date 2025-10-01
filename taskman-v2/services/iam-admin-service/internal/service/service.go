package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	pb "github.com/taskman/v2/services/iam-admin-service/pkg/api/api"
	"github.com/taskman/v2/services/iam-admin-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/queue"
	"github.com/taskman/v2/shared/pkg/validation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service implements the IAMAdminService
type Service struct {
	pb.UnimplementedIAMAdminServiceServer
	storage *storage.Storage
	cache   *cache.Cache
	queue   *queue.Queue
	log     *logger.Logger
}

// Config holds service configuration
type Config struct {
	Storage *storage.Storage
	Cache   *cache.Cache
	Queue   *queue.Queue
	Logger  *logger.Logger
}

// New creates a new Service
func New(cfg *Config) *Service {
	return &Service{
		storage: cfg.Storage,
		cache:   cfg.Cache,
		queue:   cfg.Queue,
		log:     cfg.Logger,
	}
}

// Role operations

func (s *Service) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.CreateRoleResponse, error) {
	// Validate input
	v := validation.New()
	v.Required("company_id", req.CompanyId)
	v.Required("name", req.Name)

	if v.HasErrors() {
		err := v.FirstError()
		return nil, errors.InvalidArgument(err.Field, err.Message).ToGRPCError()
	}

	// Create role
	role := &storage.Role{
		ID:           storage.GenerateRoleID(),
		CompanyID:    req.CompanyId,
		Name:         req.Name,
		Description:  req.Description,
		IsSystemRole: false, // User-created roles are never system roles
		Priority:     int(req.Priority),
		Permissions:  req.Permissions,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.storage.CreateRole(ctx, role); err != nil {
		s.log.Error("failed to create role", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Invalidate permission cache for this company
	s.invalidatePermissionCache(ctx, req.CompanyId)

	// Publish event
	s.publishEvent(ctx, "iam.role.created", map[string]interface{}{
		"role_id":    role.ID,
		"company_id": role.CompanyID,
		"name":       role.Name,
	})

	return &pb.CreateRoleResponse{
		Role: roleToProto(role),
	}, nil
}

func (s *Service) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.GetRoleResponse, error) {
	if req.RoleId == "" {
		return nil, errors.InvalidArgument("role_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	role, err := s.storage.GetRole(ctx, req.RoleId, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	return &pb.GetRoleResponse{
		Role: roleToProto(role),
	}, nil
}

func (s *Service) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.UpdateRoleResponse, error) {
	if req.RoleId == "" {
		return nil, errors.InvalidArgument("role_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	// Get existing role
	role, err := s.storage.GetRole(ctx, req.RoleId, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Cannot modify system roles' basic properties
	if role.IsSystemRole {
		return nil, errors.PermissionDenied("cannot modify system role").ToGRPCError()
	}

	// Update fields
	if req.Name != "" {
		role.Name = req.Name
	}
	if req.Description != "" {
		role.Description = req.Description
	}
	if req.Permissions != nil {
		role.Permissions = req.Permissions
	}
	if req.Priority > 0 {
		role.Priority = int(req.Priority)
	}

	if err := s.storage.UpdateRole(ctx, role); err != nil {
		s.log.Error("failed to update role", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Invalidate permission cache for this company
	s.invalidatePermissionCache(ctx, req.CompanyId)

	// Publish event
	s.publishEvent(ctx, "iam.role.updated", map[string]interface{}{
		"role_id":    role.ID,
		"company_id": role.CompanyID,
	})

	return &pb.UpdateRoleResponse{
		Role: roleToProto(role),
	}, nil
}

func (s *Service) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.DeleteRoleResponse, error) {
	if req.RoleId == "" {
		return nil, errors.InvalidArgument("role_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	if err := s.storage.DeleteRole(ctx, req.RoleId, req.CompanyId); err != nil {
		s.log.Error("failed to delete role", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Invalidate permission cache for this company
	s.invalidatePermissionCache(ctx, req.CompanyId)

	// Publish event
	s.publishEvent(ctx, "iam.role.deleted", map[string]interface{}{
		"role_id":    req.RoleId,
		"company_id": req.CompanyId,
	})

	return &pb.DeleteRoleResponse{Success: true}, nil
}

func (s *Service) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	roles, err := s.storage.ListRoles(ctx, req.CompanyId, req.IncludeSystemRoles)
	if err != nil {
		s.log.Error("failed to list roles", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	pbRoles := make([]*pb.Role, 0, len(roles))
	for _, role := range roles {
		pbRoles = append(pbRoles, roleToProto(role))
	}

	return &pb.ListRolesResponse{
		Roles: pbRoles,
	}, nil
}

// User-Role assignments

func (s *Service) AssignRole(ctx context.Context, req *pb.AssignRoleRequest) (*pb.AssignRoleResponse, error) {
	// Validate input
	v := validation.New()
	v.Required("user_id", req.UserId)
	v.Required("role_id", req.RoleId)
	v.Required("company_id", req.CompanyId)
	v.Required("assigned_by", req.AssignedBy)

	if v.HasErrors() {
		err := v.FirstError()
		return nil, errors.InvalidArgument(err.Field, err.Message).ToGRPCError()
	}

	// Verify role exists
	_, err := s.storage.GetRole(ctx, req.RoleId, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Create user-role assignment
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		expiresAt = &t
	}

	userRole := &storage.UserRole{
		ID:         storage.GenerateUserRoleID(),
		UserID:     req.UserId,
		RoleID:     req.RoleId,
		CompanyID:  req.CompanyId,
		AssignedBy: req.AssignedBy,
		AssignedAt: time.Now(),
		ExpiresAt:  expiresAt,
	}

	if err := s.storage.AssignRole(ctx, userRole); err != nil {
		s.log.Error("failed to assign role", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Invalidate user permission cache
	s.invalidateUserPermissionCache(ctx, req.UserId, req.CompanyId)

	// Publish event
	s.publishEvent(ctx, "iam.role.assigned", map[string]interface{}{
		"user_id":     req.UserId,
		"role_id":     req.RoleId,
		"company_id":  req.CompanyId,
		"assigned_by": req.AssignedBy,
	})

	return &pb.AssignRoleResponse{
		UserRole: userRoleToProto(userRole),
	}, nil
}

func (s *Service) RevokeRole(ctx context.Context, req *pb.RevokeRoleRequest) (*pb.RevokeRoleResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.RoleId == "" {
		return nil, errors.InvalidArgument("role_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	if err := s.storage.RevokeRole(ctx, req.UserId, req.RoleId, req.CompanyId); err != nil {
		s.log.Error("failed to revoke role", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Invalidate user permission cache
	s.invalidateUserPermissionCache(ctx, req.UserId, req.CompanyId)

	// Publish event
	s.publishEvent(ctx, "iam.role.revoked", map[string]interface{}{
		"user_id":    req.UserId,
		"role_id":    req.RoleId,
		"company_id": req.CompanyId,
	})

	return &pb.RevokeRoleResponse{Success: true}, nil
}

func (s *Service) GetUserRoles(ctx context.Context, req *pb.GetUserRolesRequest) (*pb.GetUserRolesResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	// Try cache first
	cacheKey := fmt.Sprintf("user_roles:%s:%s", req.CompanyId, req.UserId)
	if s.cache != nil {
		var cachedResp *pb.GetUserRolesResponse
		if _, err := s.cache.Get(ctx, cacheKey); err == nil {
			// Note: In production, unmarshal the cached data properly
			// For now, skip cache and fetch fresh data
			s.log.Debug("cache miss for user roles", "user_id", req.UserId)
		} else if cachedResp != nil {
			s.log.Debug("cache hit for user roles", "user_id", req.UserId)
			return cachedResp, nil
		}
	}

	roles, err := s.storage.GetUserRoles(ctx, req.UserId, req.CompanyId)
	if err != nil {
		s.log.Error("failed to get user roles", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Get all permissions and check if admin
	permissions, isAdmin, err := s.storage.GetUserPermissions(ctx, req.UserId, req.CompanyId)
	if err != nil {
		s.log.Error("failed to get user permissions", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Extract role names
	roleNames := make([]string, 0, len(roles))
	pbRoles := make([]*pb.Role, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		pbRoles = append(pbRoles, roleToProto(role))
	}

	response := &pb.GetUserRolesResponse{
		Roles:          pbRoles,
		RoleNames:      roleNames,
		AllPermissions: permissions,
		IsAdmin:        isAdmin,
	}

	// Cache the response for 5 minutes
	if s.cache != nil {
		if err := s.cache.Set(ctx, cacheKey, response, 5*time.Minute); err != nil {
			s.log.Warn("failed to cache user roles", "error", err)
		}
	}

	return response, nil
}

func (s *Service) ListUsersByRole(ctx context.Context, req *pb.ListUsersByRoleRequest) (*pb.ListUsersByRoleResponse, error) {
	if req.RoleId == "" {
		return nil, errors.InvalidArgument("role_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	userIDs, err := s.storage.ListUsersByRole(ctx, req.RoleId, req.CompanyId)
	if err != nil {
		s.log.Error("failed to list users by role", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	return &pb.ListUsersByRoleResponse{
		UserIds:    userIDs,
		TotalCount: int32(len(userIDs)),
	}, nil
}

// Permission checks

func (s *Service) GetUserPermissions(ctx context.Context, req *pb.GetUserPermissionsRequest) (*pb.GetUserPermissionsResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	permissions, isAdmin, err := s.storage.GetUserPermissions(ctx, req.UserId, req.CompanyId)
	if err != nil {
		s.log.Error("failed to get user permissions", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	return &pb.GetUserPermissionsResponse{
		Permissions: permissions,
		IsAdmin:     isAdmin,
	}, nil
}

func (s *Service) HasPermission(ctx context.Context, req *pb.HasPermissionRequest) (*pb.HasPermissionResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}
	if req.Permission == "" {
		return nil, errors.InvalidArgument("permission", "is required").ToGRPCError()
	}

	// Try cache first
	cacheKey := fmt.Sprintf("permission:%s:%s:%s", req.CompanyId, req.UserId, req.Permission)
	if s.cache != nil {
		var cached bool
		if _, err := s.cache.Get(ctx, cacheKey); err == nil {
			cached = true
			return &pb.HasPermissionResponse{
				Allowed: cached,
				Reason:  "cached",
			}, nil
		}
	}

	allowed, reason := s.storage.HasPermission(ctx, req.UserId, req.CompanyId, req.Permission)

	// Cache the result
	if s.cache != nil && allowed {
		// Cache for 5 minutes
		s.cache.Set(ctx, cacheKey, true, 5*time.Minute)
	}

	return &pb.HasPermissionResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

// System initialization

func (s *Service) InitializeSystemRoles(ctx context.Context, req *pb.InitializeSystemRolesRequest) (*pb.InitializeSystemRolesResponse, error) {
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	roles, err := s.storage.InitializeSystemRoles(ctx, req.CompanyId)
	if err != nil {
		s.log.Error("failed to initialize system roles", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	pbRoles := make([]*pb.Role, 0, len(roles))
	for _, role := range roles {
		pbRoles = append(pbRoles, roleToProto(role))
	}

	return &pb.InitializeSystemRolesResponse{
		CreatedRoles: pbRoles,
	}, nil
}

func (s *Service) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Status:    "healthy",
		Timestamp: timestamppb.Now(),
	}, nil
}

// Helper functions

func (s *Service) publishEvent(ctx context.Context, eventType string, payload map[string]interface{}) {
	if s.queue == nil {
		return
	}

	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	if err := s.queue.Publish(ctx, eventType, event); err != nil {
		s.log.Warn("failed to publish event", "event_type", eventType, "error", err)
	}
}

func (s *Service) invalidatePermissionCache(ctx context.Context, companyID string) {
	if s.cache == nil {
		return
	}

	// Invalidate all permission caches for this company
	pattern := fmt.Sprintf("permission:%s:*", companyID)
	if err := s.cache.DeletePattern(ctx, pattern); err != nil {
		s.log.Warn("failed to invalidate permission cache", "error", err)
	}

	// Invalidate all user role caches for this company
	pattern = fmt.Sprintf("user_roles:%s:*", companyID)
	if err := s.cache.DeletePattern(ctx, pattern); err != nil {
		s.log.Warn("failed to invalidate user roles cache", "error", err)
	}
}

func (s *Service) invalidateUserPermissionCache(ctx context.Context, userID, companyID string) {
	if s.cache == nil {
		return
	}

	// Invalidate specific user's permission cache
	pattern := fmt.Sprintf("permission:%s:%s:*", companyID, userID)
	if err := s.cache.DeletePattern(ctx, pattern); err != nil {
		s.log.Warn("failed to invalidate user permission cache", "error", err)
	}

	// Invalidate user roles cache
	cacheKey := fmt.Sprintf("user_roles:%s:%s", companyID, userID)
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.log.Warn("failed to invalidate user roles cache", "error", err)
	}
}

func roleToProto(role *storage.Role) *pb.Role {
	return &pb.Role{
		Id:           role.ID,
		CompanyId:    role.CompanyID,
		Name:         role.Name,
		Description:  role.Description,
		IsSystemRole: role.IsSystemRole,
		Priority:     int32(role.Priority),
		Permissions:  role.Permissions,
		CreatedAt:    timestamppb.New(role.CreatedAt),
		UpdatedAt:    timestamppb.New(role.UpdatedAt),
	}
}

func userRoleToProto(userRole *storage.UserRole) *pb.UserRole {
	var expiresAt *timestamppb.Timestamp
	if userRole.ExpiresAt != nil {
		expiresAt = timestamppb.New(*userRole.ExpiresAt)
	}

	return &pb.UserRole{
		Id:         userRole.ID,
		UserId:     userRole.UserID,
		RoleId:     userRole.RoleID,
		CompanyId:  userRole.CompanyID,
		AssignedBy: userRole.AssignedBy,
		AssignedAt: timestamppb.New(userRole.AssignedAt),
		ExpiresAt:  expiresAt,
	}
}
