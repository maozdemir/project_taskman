package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/taskman/v2/services/user-service/internal/service"
	"github.com/taskman/v2/services/user-service/internal/storage"
	pb "github.com/taskman/v2/services/user-service/pkg/api/api"
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

func main() {
	// Initialize logger
	log := logger.New("user-service", "info", true)

	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "50053"
	}

	log.Info("starting user service",
		slog.String("service", "user-service"),
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
	log.Info("connected to database", slog.String("service", "user-service"))

	// Initialize cache
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	redisPassword := os.Getenv("REDIS_PASSWORD")

	cacheClient, err := cache.New(&cache.Config{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       2, // User service uses DB 2
	})
	if err != nil {
		log.Warn("failed to connect to cache (continuing without cache)", "error", err)
		cacheClient = nil
	} else {
		defer cacheClient.Close()
		log.Info("connected to cache", slog.String("service", "user-service"))
	}

	// Initialize queue
	rabbitmqURI := os.Getenv("RABBITMQ_URI")
	if rabbitmqURI == "" {
		rabbitmqURI = "amqp://guest:guest@localhost:5672/"
	}

	queueClient, err := queue.New(&queue.Config{
		URI:          rabbitmqURI,
		ExchangeName: "user.events",
		ExchangeType: "topic",
	})
	if err != nil {
		log.Warn("failed to connect to queue (continuing without event publishing)", "error", err)
		queueClient = nil
	} else {
		defer queueClient.Close()
		log.Info("connected to queue", slog.String("service", "user-service"))
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

	// Initialize permission checker (connects to IAM Admin Service)
	iamServiceAddr := os.Getenv("IAM_SERVICE_ADDR")
	if iamServiceAddr == "" {
		iamServiceAddr = "localhost:50054"
	}

	permissionChecker, err := authz.NewChecker(&authz.Config{
		IAMServiceAddr: iamServiceAddr,
		Cache:          cacheClient,
		Logger:         log,
	})
	if err != nil {
		log.Error("failed to create permission checker", "error", err)
		os.Exit(1)
	}
	log.Info("permission checker initialized", "iam_service", iamServiceAddr)

	// Initialize audit logger
	auditLogger := authz.NewAuditLogger(queueClient, log)
	log.Info("audit logger initialized")

	// Define public methods (used by other services)
	publicMethods := []string{
		"/user.v1.UserService/GetUserByEmail", // Used by auth service
		"/user.v1.UserService/VerifyPassword", // Used by auth service
		"/user.v1.UserService/ListUsers",      // Used by admin panel
		"/user.v1.UserService/HealthCheck",    // Always public
	}

	// Setup authentication middleware
	authInterceptor := middleware.NewAuthInterceptor(jwtManager, log, auditLogger, publicMethods)
	log.Info("authentication interceptor configured", "public_methods", len(publicMethods))

	// Setup authorization middleware (permission map is built-in)
	authzInterceptor := middleware.NewAuthorizationInterceptor(
		permissionChecker,
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
	pb.RegisterUserServiceServer(grpcServer, svc)

	// Register health check
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("user-service", grpc_health_v1.HealthCheckResponse_SERVING)

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

	log.Info("shutting down user service")
	healthServer.SetServingStatus("user-service", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpcServer.GracefulStop()
	log.Info("user service stopped")
}
