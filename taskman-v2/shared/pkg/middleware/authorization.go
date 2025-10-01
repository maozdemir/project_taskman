package middleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/taskman/v2/shared/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PermissionChecker is an interface for checking permissions
type PermissionChecker interface {
	HasPermission(ctx context.Context, userID, companyID, permission string) (bool, string, error)
}

// AuditLogger interface for logging authorization events
type AuditLogger interface {
	LogAuthorizationFailure(ctx context.Context, method, permission, reason string)
	LogSuccessfulAuthorization(ctx context.Context, method, permission string)
}

// AuthorizationInterceptor creates a gRPC interceptor for permission checking
type AuthorizationInterceptor struct {
	checker           PermissionChecker
	log               *logger.Logger
	auditLogger       AuditLogger
	methodPermissions map[string]string // Maps gRPC methods to required permissions
}

// NewAuthorizationInterceptor creates a new authorization interceptor
func NewAuthorizationInterceptor(checker PermissionChecker, log *logger.Logger, auditLogger AuditLogger) *AuthorizationInterceptor {
	return &AuthorizationInterceptor{
		checker:           checker,
		log:               log,
		auditLogger:       auditLogger,
		methodPermissions: buildMethodPermissionMap(),
	}
}

// Unary returns a server interceptor function for unary RPCs
func (a *AuthorizationInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if method requires permission
		permission := a.getRequiredPermission(info.FullMethod)
		if permission == "" {
			// No permission required (e.g., public endpoints, health checks)
			return handler(ctx, req)
		}

		// Authorize request
		if err := a.authorize(ctx, permission, info.FullMethod); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// Stream returns a server interceptor function for stream RPCs
func (a *AuthorizationInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Check if method requires permission
		permission := a.getRequiredPermission(info.FullMethod)
		if permission == "" {
			return handler(srv, stream)
		}

		// Authorize request
		if err := a.authorize(stream.Context(), permission, info.FullMethod); err != nil {
			return err
		}

		return handler(srv, stream)
	}
}

// authorize checks if the user has the required permission
func (a *AuthorizationInterceptor) authorize(ctx context.Context, permission, method string) error {
	// Extract user and company from context (set by auth middleware)
	userID := GetUserID(ctx)
	companyID := GetCompanyID(ctx)

	if userID == "" || companyID == "" {
		a.log.Error("authorization failed: missing user or company context",
			"method", method,
			"permission", permission)
		return status.Error(codes.Unauthenticated, "missing authentication context")
	}

	// Check permission
	allowed, reason, err := a.checker.HasPermission(ctx, userID, companyID, permission)
	if err != nil {
		a.log.Error("permission check failed",
			"method", method,
			"user_id", userID,
			"company_id", companyID,
			"permission", permission,
			"error", err)
		return status.Error(codes.Internal, "permission check failed")
	}

	if !allowed {
		a.log.Warn("permission denied",
			"method", method,
			"user_id", userID,
			"company_id", companyID,
			"permission", permission,
			"reason", reason)

		// Log to audit service
		if a.auditLogger != nil {
			a.auditLogger.LogAuthorizationFailure(ctx, method, permission, reason)
		}

		return status.Errorf(codes.PermissionDenied, "insufficient permissions: %s", reason)
	}

	a.log.Debug("permission granted",
		"method", method,
		"user_id", userID,
		"company_id", companyID,
		"permission", permission)

	// Optionally log successful authorizations (only for sensitive operations)
	// Uncomment to enable:
	// if a.auditLogger != nil {
	// 	a.auditLogger.LogSuccessfulAuthorization(ctx, method, permission)
	// }

	return nil
}

// getRequiredPermission returns the permission required for a given gRPC method
func (a *AuthorizationInterceptor) getRequiredPermission(fullMethod string) string {
	if perm, ok := a.methodPermissions[fullMethod]; ok {
		return perm
	}

	// Try to infer permission from method name if not explicitly mapped
	return inferPermissionFromMethod(fullMethod)
}

// buildMethodPermissionMap builds a map of gRPC methods to required permissions
func buildMethodPermissionMap() map[string]string {
	return map[string]string{
		// Task Service
		"/task.v1.TaskService/CreateTask":   "tasks:create",
		"/task.v1.TaskService/GetTask":      "tasks:read",
		"/task.v1.TaskService/UpdateTask":   "tasks:update",
		"/task.v1.TaskService/DeleteTask":   "tasks:delete",
		"/task.v1.TaskService/ListTasks":    "tasks:read",
		"/task.v1.TaskService/AssignTask":   "tasks:assign",
		"/task.v1.TaskService/CreateProject": "projects:create",
		"/task.v1.TaskService/UpdateProject": "projects:update",
		"/task.v1.TaskService/DeleteProject": "projects:delete",

		// User Service
		"/user.v1.UserService/CreateUser":    "users:create",
		"/user.v1.UserService/GetUser":       "users:read",
		"/user.v1.UserService/UpdateUser":    "users:update",
		"/user.v1.UserService/DeleteUser":    "users:delete",
		"/user.v1.UserService/ListUsers":     "", // Public - used by admin panel
		"/user.v1.UserService/SearchUsers":   "users:read",
		"/user.v1.UserService/CreateCompany": "company:create",
		"/user.v1.UserService/UpdateCompany": "company:update",
		"/user.v1.UserService/DeleteCompany": "company:delete",
		"/user.v1.UserService/ListCompanies": "company:read",
		// Public user service methods (used by auth service)
		"/user.v1.UserService/GetUserByEmail": "",
		"/user.v1.UserService/VerifyPassword": "",

		// IAM Admin Service
		"/iam.v1.IAMAdminService/CreateRole":         "roles:create",
		"/iam.v1.IAMAdminService/UpdateRole":         "roles:update",
		"/iam.v1.IAMAdminService/DeleteRole":         "roles:delete",
		"/iam.v1.IAMAdminService/ListRoles":          "", // Public - used by admin panel
		"/iam.v1.IAMAdminService/AssignRole":         "roles:assign",
		"/iam.v1.IAMAdminService/RevokeRole":         "roles:revoke",
		"/iam.v1.IAMAdminService/GetUserRoles":       "", // Public - used by auth service during login
		"/iam.v1.IAMAdminService/GetUserPermissions": "", // Public - used by auth service during login
		"/iam.v1.IAMAdminService/HasPermission":      "", // Public - used for permission checks
		"/iam.v1.IAMAdminService/ListUsersByRole":    "roles:read",

		// Audit Service
		"/audit.v1.AuditService/QueryEvents":   "audit:read",
		"/audit.v1.AuditService/GetEventStats": "audit:read",
		"/audit.v1.AuditService/ExportEvents":  "audit:export",

		// Public endpoints (no permission required - return empty string)
		"/authentication.v1.AuthenticationService/Login":          "",
		"/authentication.v1.AuthenticationService/RefreshToken":   "",
		"/authentication.v1.AuthenticationService/HealthCheck":    "",
		"/user.v1.UserService/HealthCheck":                        "",
		"/iam.v1.IAMAdminService/HealthCheck":                     "",
		"/task.v1.TaskService/HealthCheck":                        "",
		"/audit.v1.AuditService/HealthCheck":                      "",
	}
}

// inferPermissionFromMethod attempts to infer permission from method name
// Format: /service.v1.ServiceName/MethodName -> resource:action
func inferPermissionFromMethod(fullMethod string) string {
	// Split: /service.v1.ServiceName/MethodName
	parts := strings.Split(fullMethod, "/")
	if len(parts) != 3 {
		return ""
	}

	methodName := parts[2]

	// Extract action (Create, Update, Delete, Get, List, etc.)
	var action string
	var resource string

	switch {
	case strings.HasPrefix(methodName, "Create"):
		action = "create"
		resource = strings.TrimPrefix(methodName, "Create")
	case strings.HasPrefix(methodName, "Update"):
		action = "update"
		resource = strings.TrimPrefix(methodName, "Update")
	case strings.HasPrefix(methodName, "Delete"):
		action = "delete"
		resource = strings.TrimPrefix(methodName, "Delete")
	case strings.HasPrefix(methodName, "Get"):
		action = "read"
		resource = strings.TrimPrefix(methodName, "Get")
	case strings.HasPrefix(methodName, "List"):
		action = "read"
		resource = strings.TrimPrefix(methodName, "List")
	case strings.HasPrefix(methodName, "Search"):
		action = "read"
		resource = strings.TrimPrefix(methodName, "Search")
	case strings.HasPrefix(methodName, "Assign"):
		action = "assign"
		resource = strings.TrimPrefix(methodName, "Assign")
	case strings.HasPrefix(methodName, "Revoke"):
		action = "revoke"
		resource = strings.TrimPrefix(methodName, "Revoke")
	default:
		// Unknown method pattern
		return ""
	}

	if resource == "" {
		return ""
	}

	// Convert resource to lowercase and pluralize if needed
	resource = strings.ToLower(resource)
	if !strings.HasSuffix(resource, "s") && resource != "company" {
		resource += "s"
	}

	return fmt.Sprintf("%s:%s", resource, action)
}
