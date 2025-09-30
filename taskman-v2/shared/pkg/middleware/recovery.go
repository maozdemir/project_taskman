package middleware

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/taskman/v2/shared/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryInterceptor recovers from panics and returns an internal error
func RecoveryInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				log.Error("panic recovered",
					"method", info.FullMethod,
					"panic", fmt.Sprintf("%v", r),
					"stack", string(stack),
				)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}