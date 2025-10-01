package authz

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/middleware"
	"github.com/taskman/v2/shared/pkg/queue"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// AuditLogger logs authorization events to the audit service
type AuditLogger struct {
	queue *queue.Queue
	log   *logger.Logger
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(q *queue.Queue, log *logger.Logger) *AuditLogger {
	return &AuditLogger{
		queue: q,
		log:   log,
	}
}

// LogAuthorizationFailure logs when a permission check fails
func (a *AuditLogger) LogAuthorizationFailure(
	ctx context.Context,
	method string,
	permission string,
	reason string,
) {
	if a.queue == nil {
		return
	}

	userID := middleware.GetUserID(ctx)
	companyID := middleware.GetCompanyID(ctx)
	email := middleware.GetEmail(ctx)

	// Extract IP address from context
	ipAddress := extractIPAddress(ctx)

	// Extract request ID
	requestID := extractRequestID(ctx)

	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "authz.permission.denied",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"request_id":  requestID,
			"user_id":     userID,
			"company_id":  companyID,
			"email":       email,
			"method":      method,
			"permission":  permission,
			"reason":      reason,
			"ip_address":  ipAddress,
			"severity":    "warning",
			"event_type":  "authorization",
		},
	}

	if err := a.queue.Publish(ctx, "authz.permission.denied", event); err != nil {
		a.log.Warn("failed to publish authorization failure event", "error", err)
	}
}

// LogAuthenticationFailure logs when JWT validation fails
func (a *AuditLogger) LogAuthenticationFailure(
	ctx context.Context,
	method string,
	reason string,
) {
	if a.queue == nil {
		return
	}

	ipAddress := extractIPAddress(ctx)
	requestID := extractRequestID(ctx)

	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "authz.authentication.failed",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"request_id": requestID,
			"method":     method,
			"reason":     reason,
			"ip_address": ipAddress,
			"severity":   "warning",
			"event_type": "authentication",
		},
	}

	if err := a.queue.Publish(ctx, "authz.authentication.failed", event); err != nil {
		a.log.Warn("failed to publish authentication failure event", "error", err)
	}
}

// LogCompanyIsolationViolation logs when a user tries to access another company's data
func (a *AuditLogger) LogCompanyIsolationViolation(
	ctx context.Context,
	method string,
	requestedCompanyID string,
) {
	if a.queue == nil {
		return
	}

	userID := middleware.GetUserID(ctx)
	companyID := middleware.GetCompanyID(ctx)
	email := middleware.GetEmail(ctx)
	ipAddress := extractIPAddress(ctx)
	requestID := extractRequestID(ctx)

	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "authz.company.isolation.violation",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"request_id":           requestID,
			"user_id":              userID,
			"user_company_id":      companyID,
			"requested_company_id": requestedCompanyID,
			"email":                email,
			"method":               method,
			"ip_address":           ipAddress,
			"severity":             "critical",
			"event_type":           "security",
		},
	}

	if err := a.queue.Publish(ctx, "authz.company.isolation.violation", event); err != nil {
		a.log.Warn("failed to publish company isolation violation event", "error", err)
	}
}

// LogOwnershipViolation logs when a user tries to access resources they don't own
func (a *AuditLogger) LogOwnershipViolation(
	ctx context.Context,
	method string,
	permission string,
	resourceType string,
	resourceID string,
	resourceOwnerID string,
) {
	if a.queue == nil {
		return
	}

	userID := middleware.GetUserID(ctx)
	companyID := middleware.GetCompanyID(ctx)
	email := middleware.GetEmail(ctx)
	ipAddress := extractIPAddress(ctx)
	requestID := extractRequestID(ctx)

	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "authz.ownership.violation",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"request_id":        requestID,
			"user_id":           userID,
			"company_id":        companyID,
			"email":             email,
			"method":            method,
			"permission":        permission,
			"resource_type":     resourceType,
			"resource_id":       resourceID,
			"resource_owner_id": resourceOwnerID,
			"ip_address":        ipAddress,
			"severity":          "warning",
			"event_type":        "authorization",
		},
	}

	if err := a.queue.Publish(ctx, "authz.ownership.violation", event); err != nil {
		a.log.Warn("failed to publish ownership violation event", "error", err)
	}
}

// LogSuccessfulAuthorization logs successful authorization (optional, for analytics)
func (a *AuditLogger) LogSuccessfulAuthorization(
	ctx context.Context,
	method string,
	permission string,
) {
	// Only log if explicitly enabled (to avoid excessive audit logs)
	// This can be enabled for sensitive operations only
	if a.queue == nil {
		return
	}

	userID := middleware.GetUserID(ctx)
	companyID := middleware.GetCompanyID(ctx)
	requestID := extractRequestID(ctx)

	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "authz.permission.granted",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"request_id": requestID,
			"user_id":    userID,
			"company_id": companyID,
			"method":     method,
			"permission": permission,
			"severity":   "info",
			"event_type": "authorization",
		},
	}

	// Use a separate topic for success events (can be filtered in audit service)
	if err := a.queue.Publish(ctx, "authz.permission.granted", event); err != nil {
		a.log.Warn("failed to publish authorization success event", "error", err)
	}
}

// Helper functions

func extractIPAddress(ctx context.Context) string {
	// Try to get from peer info
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}

	// Try to get from metadata (if proxied)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			return xff[0]
		}
		if xri := md.Get("x-real-ip"); len(xri) > 0 {
			return xri[0]
		}
	}

	return "unknown"
}

func extractRequestID(ctx context.Context) string {
	// Extract from context value (set by request_id middleware)
	if val := ctx.Value(middleware.RequestIDKey); val != nil {
		if reqID, ok := val.(string); ok {
			return reqID
		}
	}

	// Try to get from metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if reqID := md.Get("x-request-id"); len(reqID) > 0 {
			return reqID[0]
		}
	}

	return uuid.New().String()
}
