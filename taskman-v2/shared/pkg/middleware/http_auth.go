package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/logger"
)

// HTTPAuthMiddleware creates HTTP middleware for JWT authentication
type HTTPAuthMiddleware struct {
	jwtManager  *jwt.Manager
	log         *logger.Logger
	auditLogger AuthAuditLogger
	publicPaths map[string]bool // Paths that don't require authentication
}

// NewHTTPAuthMiddleware creates a new HTTP auth middleware
func NewHTTPAuthMiddleware(jwtManager *jwt.Manager, log *logger.Logger, auditLogger AuthAuditLogger, publicPaths []string) *HTTPAuthMiddleware {
	pathsMap := make(map[string]bool)
	for _, path := range publicPaths {
		pathsMap[path] = true
	}

	return &HTTPAuthMiddleware{
		jwtManager:  jwtManager,
		log:         log,
		auditLogger: auditLogger,
		publicPaths: pathsMap,
	}
}

// Handler wraps an HTTP handler with authentication
func (m *HTTPAuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path is public
		if m.publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Extract and validate JWT
		ctx, err := m.authenticate(r)
		if err != nil {
			m.log.Warn("HTTP authentication failed",
				"path", r.URL.Path,
				"method", r.Method,
				"error", err)

			// Log authentication failure
			if m.auditLogger != nil {
				m.auditLogger.LogAuthenticationFailure(r.Context(), r.URL.Path, err.Error())
			}

			writeErrorResponse(w, http.StatusUnauthorized, "authentication failed")
			return
		}

		// Create new request with updated context
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// authenticate extracts and validates JWT from HTTP request
func (m *HTTPAuthMiddleware) authenticate(r *http.Request) (context.Context, error) {
	// Extract authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.Unauthenticated("missing authorization header")
	}

	// Parse Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.Unauthenticated("invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify token
	claims, err := m.jwtManager.VerifyAccessToken(token)
	if err != nil {
		return nil, errors.Unauthenticated("invalid or expired token")
	}

	// Add claims to context
	ctx := r.Context()
	ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
	ctx = context.WithValue(ctx, CompanyIDKey, claims.CompanyID)
	ctx = context.WithValue(ctx, EmailKey, claims.Email)
	ctx = context.WithValue(ctx, UsernameKey, claims.Username)
	ctx = context.WithValue(ctx, RolesKey, claims.Roles)
	ctx = context.WithValue(ctx, SessionIDKey, claims.SessionID)

	return ctx, nil
}

// HTTPAuthzMiddleware creates HTTP middleware for permission checking
type HTTPAuthzMiddleware struct {
	checker       PermissionChecker
	log           *logger.Logger
	auditLogger   AuditLogger
	pathPermissions map[string]string // Maps HTTP paths to required permissions
}

// NewHTTPAuthzMiddleware creates a new HTTP authorization middleware
func NewHTTPAuthzMiddleware(checker PermissionChecker, log *logger.Logger, auditLogger AuditLogger) *HTTPAuthzMiddleware {
	return &HTTPAuthzMiddleware{
		checker:         checker,
		log:             log,
		auditLogger:     auditLogger,
		pathPermissions: buildHTTPPathPermissionMap(),
	}
}

// Handler wraps an HTTP handler with authorization
func (m *HTTPAuthzMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get required permission for this path
		permission := m.getRequiredPermission(r.URL.Path, r.Method)
		if permission == "" {
			// No permission required
			next.ServeHTTP(w, r)
			return
		}

		// Check permission
		if err := m.authorize(r.Context(), permission, r.URL.Path); err != nil {
			writeErrorResponse(w, http.StatusForbidden, "insufficient permissions")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authorize checks if the user has the required permission
func (m *HTTPAuthzMiddleware) authorize(ctx context.Context, permission, path string) error {
	userID := GetUserID(ctx)
	companyID := GetCompanyID(ctx)

	if userID == "" || companyID == "" {
		m.log.Error("authorization failed: missing user or company context",
			"path", path,
			"permission", permission)
		return errors.Unauthenticated("missing authentication context")
	}

	// Check permission
	allowed, reason, err := m.checker.HasPermission(ctx, userID, companyID, permission)
	if err != nil {
		m.log.Error("permission check failed",
			"path", path,
			"user_id", userID,
			"company_id", companyID,
			"permission", permission,
			"error", err)
		return errors.Internal("permission check failed")
	}

	if !allowed {
		m.log.Warn("permission denied",
			"path", path,
			"user_id", userID,
			"company_id", companyID,
			"permission", permission,
			"reason", reason)

		// Log to audit service
		if m.auditLogger != nil {
			m.auditLogger.LogAuthorizationFailure(ctx, path, permission, reason)
		}

		return errors.PermissionDenied(reason)
	}

	m.log.Debug("permission granted",
		"path", path,
		"user_id", userID,
		"company_id", companyID,
		"permission", permission)

	return nil
}

// getRequiredPermission returns the permission required for a given HTTP path and method
func (m *HTTPAuthzMiddleware) getRequiredPermission(path, method string) string {
	// Build key from method and path
	key := method + " " + path

	if perm, ok := m.pathPermissions[key]; ok {
		return perm
	}

	// Try to infer from path pattern
	return inferHTTPPermission(path, method)
}

// buildHTTPPathPermissionMap builds a map of HTTP paths to required permissions
func buildHTTPPathPermissionMap() map[string]string {
	return map[string]string{
		// Task endpoints
		"POST /v1/tasks":                "tasks:create",
		"GET /v1/tasks":                 "tasks:read",
		"GET /v1/tasks/:id":             "tasks:read",
		"PUT /v1/tasks/:id":             "tasks:update",
		"PATCH /v1/tasks/:id":           "tasks:update",
		"DELETE /v1/tasks/:id":          "tasks:delete",

		// User endpoints
		"POST /v1/users":                "users:create",
		"GET /v1/users":                 "users:read",
		"GET /v1/users/:id":             "users:read",
		"PUT /v1/users/:id":             "users:update",
		"PATCH /v1/users/:id":           "users:update",
		"DELETE /v1/users/:id":          "users:delete",

		// Company endpoints
		"POST /v1/companies":            "company:create",
		"GET /v1/companies":             "company:read",
		"GET /v1/companies/:id":         "company:read",
		"PUT /v1/companies/:id":         "company:update",
		"PATCH /v1/companies/:id":       "company:update",
		"DELETE /v1/companies/:id":      "company:delete",

		// Role endpoints
		"POST /v1/roles":                "roles:create",
		"GET /v1/roles":                 "roles:read",
		"GET /v1/roles/:id":             "roles:read",
		"PUT /v1/roles/:id":             "roles:update",
		"PATCH /v1/roles/:id":           "roles:update",
		"DELETE /v1/roles/:id":          "roles:delete",
		"POST /v1/roles/:id/assign":     "roles:assign",
		"POST /v1/roles/:id/revoke":     "roles:revoke",

		// Audit endpoints
		"GET /v1/audit/events":          "audit:read",
		"GET /v1/audit/stats":           "audit:read",

		// Public endpoints (no permission)
		"POST /v1/auth/login":           "",
		"POST /v1/auth/refresh":         "",
		"POST /v1/auth/logout":          "",
		"GET /v1/health":                "",
	}
}

// inferHTTPPermission attempts to infer permission from HTTP path and method
func inferHTTPPermission(path, method string) string {
	// Simple pattern matching
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}

	resource := parts[1] // e.g., "tasks", "users", "companies"

	var action string
	switch method {
	case "POST":
		action = "create"
	case "GET":
		action = "read"
	case "PUT", "PATCH":
		action = "update"
	case "DELETE":
		action = "delete"
	default:
		return ""
	}

	return resource + ":" + action
}

// writeErrorResponse writes a JSON error response
func writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write([]byte(`{"error": "` + message + `"}`))
}

// CORS middleware helper
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequestIDMiddleware adds a request ID to the context
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = GenerateRequestID()
		}

		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
		w.Header().Set("X-Request-ID", requestID)

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware(log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Info("HTTP request",
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
				"request_id", GetRequestID(r.Context()))

			next.ServeHTTP(w, r)
		})
	}
}
