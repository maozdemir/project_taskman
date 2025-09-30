package middleware

import (
	"context"
	"time"

	"github.com/taskman/v2/shared/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// LoggingInterceptor logs gRPC requests and responses
func LoggingInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Call handler
		resp, err := handler(ctx, req)

		// Calculate duration
		duration := time.Since(start).Milliseconds()

		// Get status code
		st, _ := status.FromError(err)

		// Log request
		if err != nil {
			log.Error("gRPC request failed",
				"method", info.FullMethod,
				"duration_ms", duration,
				"status", st.Code().String(),
				"error", st.Message(),
			)
		} else {
			log.Info("gRPC request",
				"method", info.FullMethod,
				"duration_ms", duration,
				"status", st.Code().String(),
			)
		}

		return resp, err
	}
}