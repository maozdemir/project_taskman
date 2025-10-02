package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/taskman/v2/services/iam-admin-service/internal/service"
	"github.com/taskman/v2/services/iam-admin-service/internal/storage"
	pb "github.com/taskman/v2/services/iam-admin-service/pkg/api/api"
	"github.com/taskman/v2/shared/pkg/authz"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/middleware"
	"github.com/taskman/v2/shared/pkg/queue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// IAMSelfPermissionChecker allows IAM service to check permissions against itself without gRPC loop
type IAMSelfPermissionChecker struct {
	service *service.Service
	logger  *logger.Logger
}

func (c *IAMSelfPermissionChecker) HasPermission(ctx context.Context, userID, companyID, permission string) (bool, string, error) {
	req := &pb.HasPermissionRequest{
		UserId:     userID,
		CompanyId:  companyID,
		Permission: permission,
	}
	resp, err := c.service.HasPermission(ctx, req)
	if err != nil {
		return false, "permission check failed", err
	}
	return resp.Allowed, resp.Reason, nil
}

func (c *IAMSelfPermissionChecker) GetUserPermissions(ctx context.Context, userID, companyID string) ([]string, bool, error) {
	req := &pb.GetUserPermissionsRequest{
		UserId:    userID,
		CompanyId: companyID,
	}
	resp, err := c.service.GetUserPermissions(ctx, req)
	if err != nil {
		return nil, false, err
	}
	return resp.Permissions, resp.IsAdmin, nil
}

func (c *IAMSelfPermissionChecker) InvalidateUserPermissions(ctx context.Context, userID, companyID string) error {
	// Cache invalidation handled by IAM service internally
	return nil
}

func main() {
	// Initialize logger
	log := logger.New("iam-admin-service", "info", true)

	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "50054"
	}

	log.Info("starting IAM admin service",
		slog.String("service", "iam-admin-service"),
		slog.String("environment", "development"),
		slog.String("grpc_port", grpcPort),
	)

	// Get database URL from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Error("DATABASE_URL environment variable is required")
		os.Exit(1)
	}

	// Initialize database
	db, err := database.New(&database.Config{
		URL:             dbURL,
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	})
	if err != nil {
		log.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	log.Info("connected to database", slog.String("service", "iam-admin-service"))

	// Initialize cache
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	redisPassword := os.Getenv("REDIS_PASSWORD")

	cacheClient, err := cache.New(&cache.Config{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       3, // IAM Admin service uses DB 3
	})
	if err != nil {
		log.Warn("failed to connect to cache (continuing without cache)", "error", err)
		cacheClient = nil
	} else {
		defer cacheClient.Close()
		log.Info("connected to cache", slog.String("service", "iam-admin-service"))
	}

	// Initialize queue
	rabbitmqURI := os.Getenv("RABBITMQ_URI")
	if rabbitmqURI == "" {
		rabbitmqURI = "amqp://guest:guest@localhost:5672/"
	}

	queueClient, err := queue.New(&queue.Config{
		URI:          rabbitmqURI,
		ExchangeName: "iam.events",
		ExchangeType: "topic",
	})
	if err != nil {
		log.Warn("failed to connect to queue (continuing without event publishing)", "error", err)
		queueClient = nil
	} else {
		defer queueClient.Close()
		log.Info("connected to queue", slog.String("service", "iam-admin-service"))
	}

	// Initialize storage
	storageInst := storage.New(db)

	// Initialize service
	svc := service.New(&service.Config{
		Storage: storageInst,
		Cache:   cacheClient,
		Queue:   queueClient,
		Logger:  log,
	})

	// ===== RBAC INTEGRATION =====

	// Initialize JWT manager
	jwtAccessSecret := os.Getenv("JWT_ACCESS_SECRET")
	jwtRefreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if jwtAccessSecret == "" || jwtRefreshSecret == "" {
		log.Error("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are required for RBAC")
		os.Exit(1)
	}

	jwtManager := jwt.NewManager(
		jwtAccessSecret,
		jwtRefreshSecret,
		15*time.Minute,
		7*24*time.Hour,
	)
	log.Info("JWT manager initialized")

	// Initialize audit logger
	auditLogger := authz.NewAuditLogger(queueClient, log)
	log.Info("audit logger initialized")

	// Define public methods (used by all services for permission checks)
	// Note: Role management methods now require authentication so that user/company context is available for authorization
	publicMethods := []string{
		"/iam.v1.IAMAdminService/HasPermission",      // Used by all services
		"/iam.v1.IAMAdminService/GetUserRoles",       // Used by all services
		"/iam.v1.IAMAdminService/GetUserPermissions", // Used by all services
		"/iam.v1.IAMAdminService/HealthCheck",        // Always public
	}

	// Setup authentication middleware
	authInterceptor := middleware.NewAuthInterceptor(jwtManager, log, auditLogger, publicMethods)
	log.Info("authentication interceptor configured", "public_methods", len(publicMethods))

	// Setup self-permission checker (IAM can't call itself via gRPC)
	selfPermissionChecker := &IAMSelfPermissionChecker{
		service: svc,
		logger:  log,
	}

	// Setup authorization middleware (permission map is built-in)
	authzInterceptor := middleware.NewAuthorizationInterceptor(
		selfPermissionChecker,
		log,
		auditLogger,
	)
	log.Info("authorization interceptor configured")

	// Create gRPC server with full RBAC middleware chain
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			middleware.RequestIDInterceptor(),
			middleware.LoggingInterceptor(log),
			middleware.RecoveryInterceptor(log),
			authInterceptor.Unary(),
			authzInterceptor.Unary(),
		),
		grpc.MaxRecvMsgSize(10*1024*1024),
		grpc.MaxSendMsgSize(10*1024*1024),
		grpc.ConnectionTimeout(30*time.Second),
	)

	// Register services
	pb.RegisterIAMAdminServiceServer(grpcServer, svc)

	// Register health check
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("iam-admin-service", grpc_health_v1.HealthCheckResponse_SERVING)

	// Register reflection for debugging
	reflection.Register(grpcServer)

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", grpcPort))
	if err != nil {
		log.Error("failed to listen", "error", err)
		os.Exit(1)
	}

	go func() {
		log.Info("gRPC server listening", slog.String("addr", lis.Addr().String()))
		if err := grpcServer.Serve(lis); err != nil {
			log.Error("gRPC server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("shutting down IAM admin service")
	healthServer.SetServingStatus("iam-admin-service", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpcServer.GracefulStop()
	log.Info("IAM admin service stopped")
}
