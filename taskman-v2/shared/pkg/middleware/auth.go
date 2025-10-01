package middleware

import (
	"context"
	"strings"

	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// UserIDKey is the context key for user ID
	UserIDKey contextKey = "user_id"
	// CompanyIDKey is the context key for company ID
	CompanyIDKey contextKey = "company_id"
	// EmailKey is the context key for email
	EmailKey contextKey = "email"
	// UsernameKey is the context key for username
	UsernameKey contextKey = "username"
	// RolesKey is the context key for roles
	RolesKey contextKey = "roles"
	// SessionIDKey is the context key for session ID
	SessionIDKey contextKey = "session_id"
)

// AuthAuditLogger interface for logging authentication events
type AuthAuditLogger interface {
	LogAuthenticationFailure(ctx context.Context, method, reason string)
}

// AuthInterceptor creates a gRPC interceptor for JWT authentication
type AuthInterceptor struct {
	jwtManager      *jwt.Manager
	log             *logger.Logger
	auditLogger     AuthAuditLogger
	publicMethods   map[string]bool // Methods that don't require authentication
}

// NewAuthInterceptor creates a new auth interceptor
func NewAuthInterceptor(jwtManager *jwt.Manager, log *logger.Logger, auditLogger AuthAuditLogger, publicMethods []string) *AuthInterceptor {
	methodsMap := make(map[string]bool)
	for _, method := range publicMethods {
		methodsMap[method] = true
	}

	return &AuthInterceptor{
		jwtManager:    jwtManager,
		log:           log,
		auditLogger:   auditLogger,
		publicMethods: methodsMap,
	}
}

// Unary returns a server interceptor function for unary RPCs
func (a *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if method is public
		if a.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract and validate JWT token
		newCtx, err := a.authenticate(ctx)
		if err != nil {
			a.log.Warn("authentication failed",
				"method", info.FullMethod,
				"error", err)
			return nil, err
		}

		return handler(newCtx, req)
	}
}

// Stream returns a server interceptor function for stream RPCs
func (a *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Check if method is public
		if a.publicMethods[info.FullMethod] {
			return handler(srv, stream)
		}

		// Extract and validate JWT token
		newCtx, err := a.authenticate(stream.Context())
		if err != nil {
			a.log.Warn("authentication failed",
				"method", info.FullMethod,
				"error", err)
			return err
		}

		wrapped := &wrappedStream{
			ServerStream: stream,
			ctx:          newCtx,
		}

		return handler(srv, wrapped)
	}
}

// authenticate extracts and validates the JWT token from the request
func (a *AuthInterceptor) authenticate(ctx context.Context) (context.Context, error) {
	// Extract metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		err := errors.Unauthenticated("missing metadata").ToGRPCError()
		if a.auditLogger != nil {
			a.auditLogger.LogAuthenticationFailure(ctx, "unknown", "missing metadata")
		}
		return nil, err
	}

	// Extract authorization header
	values := md.Get("authorization")
	if len(values) == 0 {
		err := errors.Unauthenticated("missing authorization header").ToGRPCError()
		if a.auditLogger != nil {
			a.auditLogger.LogAuthenticationFailure(ctx, "unknown", "missing authorization header")
		}
		return nil, err
	}

	// Parse Bearer token
	authHeader := values[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		err := errors.Unauthenticated("invalid authorization header format").ToGRPCError()
		if a.auditLogger != nil {
			a.auditLogger.LogAuthenticationFailure(ctx, "unknown", "invalid authorization header format")
		}
		return nil, err
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify token
	claims, err := a.jwtManager.VerifyAccessToken(token)
	if err != nil {
		authErr := errors.Unauthenticated("invalid or expired token").ToGRPCError()
		if a.auditLogger != nil {
			a.auditLogger.LogAuthenticationFailure(ctx, "unknown", "invalid or expired token")
		}
		return nil, authErr
	}

	// Add claims to context
	ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
	ctx = context.WithValue(ctx, CompanyIDKey, claims.CompanyID)
	ctx = context.WithValue(ctx, EmailKey, claims.Email)
	ctx = context.WithValue(ctx, UsernameKey, claims.Username)
	ctx = context.WithValue(ctx, RolesKey, claims.Roles)
	ctx = context.WithValue(ctx, SessionIDKey, claims.SessionID)

	return ctx, nil
}

// wrappedStream wraps a grpc.ServerStream with a custom context
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

// Helper functions to extract claims from context

// GetUserID extracts the user ID from context
func GetUserID(ctx context.Context) string {
	if val := ctx.Value(UserIDKey); val != nil {
		return val.(string)
	}
	return ""
}

// GetCompanyID extracts the company ID from context
func GetCompanyID(ctx context.Context) string {
	if val := ctx.Value(CompanyIDKey); val != nil {
		return val.(string)
	}
	return ""
}

// GetEmail extracts the email from context
func GetEmail(ctx context.Context) string {
	if val := ctx.Value(EmailKey); val != nil {
		return val.(string)
	}
	return ""
}

// GetUsername extracts the username from context
func GetUsername(ctx context.Context) string {
	if val := ctx.Value(UsernameKey); val != nil {
		return val.(string)
	}
	return ""
}

// GetRoles extracts the roles from context
func GetRoles(ctx context.Context) []string {
	if val := ctx.Value(RolesKey); val != nil {
		return val.([]string)
	}
	return []string{}
}

// GetSessionID extracts the session ID from context
func GetSessionID(ctx context.Context) string {
	if val := ctx.Value(SessionIDKey); val != nil {
		return val.(string)
	}
	return ""
}

// ValidateCompanyAccess ensures the request's company_id matches JWT company_id
func ValidateCompanyAccess(ctx context.Context, requestCompanyID string) error {
	jwtCompanyID := GetCompanyID(ctx)
	if jwtCompanyID == "" {
		return errors.Unauthenticated("missing company context").ToGRPCError()
	}

	if requestCompanyID != jwtCompanyID {
		return errors.PermissionDenied("company_id mismatch - access to other company data denied").ToGRPCError()
	}

	return nil
}

// ValidateCompanyAccessWithAudit validates company access and logs violations
func ValidateCompanyAccessWithAudit(ctx context.Context, requestCompanyID string, method string, auditLogger AuthAuditLogger) error {
	jwtCompanyID := GetCompanyID(ctx)
	if jwtCompanyID == "" {
		return errors.Unauthenticated("missing company context").ToGRPCError()
	}

	if requestCompanyID != jwtCompanyID {
		// Log company isolation violation
		if auditLogger != nil {
			// Cast to access the full audit logger interface
			if fullLogger, ok := auditLogger.(interface {
				LogCompanyIsolationViolation(ctx context.Context, method, requestedCompanyID string)
			}); ok {
				fullLogger.LogCompanyIsolationViolation(ctx, method, requestCompanyID)
			}
		}
		return errors.PermissionDenied("company_id mismatch - access to other company data denied").ToGRPCError()
	}

	return nil
}
