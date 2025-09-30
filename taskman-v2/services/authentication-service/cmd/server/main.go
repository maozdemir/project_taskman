package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/taskman/v2/services/authentication-service/pkg/api/api"
	"github.com/taskman/v2/services/authentication-service/internal/service"
	"github.com/taskman/v2/services/authentication-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/config"
	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/health"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/middleware"
	"github.com/taskman/v2/shared/pkg/queue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Load configuration
	cfg := config.LoadBaseConfig("authentication-service", 8080, 50051, 9090)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	// Initialize logger
	logger := logger.New(cfg.ServiceName, cfg.LogLevel, cfg.IsDevelopment())
	logger.Info("starting authentication service",
		"environment", cfg.Environment,
		"grpc_port", cfg.GRPCPort,
	)

	// Initialize database
	db, err := database.New(&database.Config{
		URL:             cfg.DatabaseURL,
		MaxOpenConns:    cfg.DBMaxConns,
		MaxIdleConns:    cfg.DBMaxIdle,
		ConnMaxLifetime: 1 * time.Hour,
		ConnMaxIdleTime: 10 * time.Minute,
	})
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("connected to database")

	// Initialize cache
	cacheClient, err := cache.New(&cache.Config{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err != nil {
		logger.Error("failed to connect to cache", "error", err)
		os.Exit(1)
	}
	defer cacheClient.Close()
	logger.Info("connected to cache")

	// Initialize queue
	queueClient, err := queue.New(&queue.Config{
		URI:              cfg.RabbitMQURI,
		ExchangeName:     "auth.events",
		ExchangeType:     "topic",
		PrefetchCount:    10,
		ReconnectDelay:   5 * time.Second,
		PublishTimeout:   5 * time.Second,
		EnableCircuitBreaker: true,
	})
	if err != nil {
		logger.Error("failed to connect to queue", "error", err)
		os.Exit(1)
	}
	defer queueClient.Close()
	logger.Info("connected to queue")

	// Initialize JWT manager
	jwtManager := jwt.NewManager(
		cfg.JWTAccessSecret,
		cfg.JWTRefreshSecret,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
	)
	logger.Info("initialized JWT manager")

	// Initialize storage
	store := storage.New(db)

	// Initialize service
	svc := service.New(&service.Config{
		Storage:    store,
		Cache:      cacheClient,
		Queue:      queueClient,
		JWTManager: jwtManager,
		Logger:     logger,
	})

	// Initialize health checker
	healthChecker := health.New()
	healthChecker.RegisterFunc("database", db.Health)
	healthChecker.RegisterFunc("cache", cacheClient.Health)
	healthChecker.RegisterFunc("queue", queueClient.Health)

	// Create gRPC server with interceptors
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			middleware.RequestIDInterceptor(),
			middleware.LoggingInterceptor(logger),
			middleware.RecoveryInterceptor(logger),
		),
	)

	// Register service
	pb.RegisterAuthenticationServiceServer(grpcServer, svc)

	// Enable reflection for grpcurl
	reflection.Register(grpcServer)

	// Start listening
	addr := fmt.Sprintf(":%d", cfg.GRPCPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("failed to listen", "error", err, "addr", addr)
		os.Exit(1)
	}

	// Start server in goroutine
	go func() {
		logger.Info("gRPC server listening", "addr", addr)
		if err := grpcServer.Serve(listener); err != nil {
			logger.Error("failed to serve", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	// Graceful stop with timeout
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()

	// Wait for graceful stop or force stop after 30 seconds
	select {
	case <-stopped:
		logger.Info("server stopped gracefully")
	case <-time.After(30 * time.Second):
		grpcServer.Stop()
		logger.Warn("server force stopped")
	}

	logger.Info("server shutdown complete")
}