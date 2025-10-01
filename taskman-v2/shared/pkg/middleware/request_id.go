package middleware

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// RequestIDKey is exported for use in other middleware
const RequestIDKey contextKey = "request_id"

// RequestIDInterceptor adds a request ID to the context
func RequestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Try to get request ID from metadata
		requestID := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if ids := md.Get("x-request-id"); len(ids) > 0 {
				requestID = ids[0]
			}
		}

		// Generate new request ID if not present
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Add to context
		ctx = context.WithValue(ctx, RequestIDKey, requestID)

		// Add to outgoing metadata
		ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID)

		return handler(ctx, req)
	}
}

// GetRequestID retrieves request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// GenerateRequestID generates a new unique request ID
func GenerateRequestID() string {
	return uuid.New().String()
}