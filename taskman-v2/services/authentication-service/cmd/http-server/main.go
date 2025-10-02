package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/taskman/v2/services/authentication-service/internal/clients"
	"github.com/taskman/v2/services/authentication-service/internal/handlers"
	"github.com/taskman/v2/services/authentication-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/httputil"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/queue"
	_ "github.com/lib/pq"
)

var logger *slog.Logger

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return httputil.CORSMiddleware(next)
}

func main() {
	// Initialize logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	logger.Info("starting authentication HTTP service", slog.String("service", "authentication-http"), slog.String("environment", "development"), slog.String("http_port", httpPort))

	// Get database URL from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logger.Error("DATABASE_URL environment variable is required")
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
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("connected to database", slog.String("service", "authentication-http"))

	// Initialize cache
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	redisPassword := os.Getenv("REDIS_PASSWORD")

	cacheClient, err := cache.New(&cache.Config{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       0,
	})
	if err != nil {
		logger.Error("failed to connect to cache", "error", err)
		os.Exit(1)
	}
	defer cacheClient.Close()
	logger.Info("connected to cache", slog.String("service", "authentication-http"))

	// Initialize queue
	rabbitmqURI := os.Getenv("RABBITMQ_URI")
	if rabbitmqURI == "" {
		rabbitmqURI = "amqp://guest:guest@localhost:5672/"
	}

	queueClient, err := queue.New(&queue.Config{
		URI:          rabbitmqURI,
		ExchangeName: "taskman",
		ExchangeType: "topic",
	})
	if err != nil {
		logger.Warn("failed to connect to queue (will continue without event publishing)", "error", err)
		queueClient = nil
	} else {
		defer queueClient.Close()
		logger.Info("connected to queue", slog.String("service", "authentication-http"))
	}

	// Initialize JWT manager
	jwtAccessSecret := os.Getenv("JWT_ACCESS_SECRET")
	jwtRefreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if jwtAccessSecret == "" || jwtRefreshSecret == "" {
		logger.Error("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET environment variables are required")
		os.Exit(1)
	}

	jwtManager := jwt.NewManager(jwtAccessSecret, jwtRefreshSecret, 15*time.Minute, 7*24*time.Hour)
	logger.Info("initialized JWT manager", slog.String("service", "authentication-http"))

	// Initialize storage
	storageInst := storage.New(db)

	// Initialize gRPC clients for microservices
	userServiceAddr := os.Getenv("USER_SERVICE_ADDR")
	if userServiceAddr == "" {
		userServiceAddr = "localhost:50053"
	}
	userClient, err := clients.NewUserClient(userServiceAddr)
	if err != nil {
		logger.Error("failed to connect to User Service", "error", err)
		os.Exit(1)
	}
	defer userClient.Close()
	logger.Info("connected to User Service", "addr", userServiceAddr)

	iamServiceAddr := os.Getenv("IAM_SERVICE_ADDR")
	if iamServiceAddr == "" {
		iamServiceAddr = "localhost:50054"
	}
	iamClient, err := clients.NewIAMClient(iamServiceAddr)
	if err != nil {
		logger.Error("failed to connect to IAM Admin Service", "error", err)
		os.Exit(1)
	}
	defer iamClient.Close()
	logger.Info("connected to IAM Admin Service", "addr", iamServiceAddr)

	auditServiceAddr := os.Getenv("AUDIT_SERVICE_ADDR")
	if auditServiceAddr == "" {
		auditServiceAddr = "localhost:50056"
	}
	auditClient, err := clients.NewAuditClient(auditServiceAddr)
	if err != nil {
		logger.Error("failed to connect to Audit Service", "error", err)
		os.Exit(1)
	}
	defer auditClient.Close()
	logger.Info("connected to Audit Service", "addr", auditServiceAddr)

	// Initialize handler with all dependencies
	handler := &handlers.Handler{
		DB:          db,
		Cache:       cacheClient,
		Queue:       queueClient,
		JWTManager:  jwtManager,
		Storage:     storageInst,
		UserClient:  userClient,
		IAMClient:   iamClient,
		AuditClient: auditClient,
		Logger:      logger,
	}

	// Setup routes
	mux := http.NewServeMux()

	// Authentication routes
	mux.HandleFunc("/api/v1/auth/login", corsMiddleware(handler.HandleLogin))
	mux.HandleFunc("/api/v1/auth/register", corsMiddleware(handler.HandleRegister))
	mux.HandleFunc("/api/v1/auth/refresh", corsMiddleware(handler.HandleRefresh))
	mux.HandleFunc("/api/v1/auth/logout", corsMiddleware(handler.HandleLogout))
	mux.HandleFunc("/api/v1/auth/validate", corsMiddleware(handler.HandleValidate))
	mux.HandleFunc("/api/v1/auth/me", corsMiddleware(handler.HandleMe))

	// User management routes
	mux.HandleFunc("/api/v1/users", corsMiddleware(handler.HandleListUsers))
	mux.HandleFunc("/api/v1/users/", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handler.HandleGetUser(w, r)
		case http.MethodPut:
			handler.HandleUpdateUser(w, r)
		case http.MethodDelete:
			handler.HandleDeleteUser(w, r)
		case http.MethodPost:
			handler.HandleCreateUser(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// IAM routes - Roles
	mux.HandleFunc("/api/v1/iam/roles", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handler.HandleListRoles(w, r)
		case http.MethodPost:
			handler.HandleCreateRole(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/iam/roles/", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handler.HandleGetRole(w, r)
		case http.MethodPut:
			handler.HandleUpdateRole(w, r)
		case http.MethodDelete:
			handler.HandleDeleteRole(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// IAM routes - Role assignments
	mux.HandleFunc("/api/v1/iam/roles/assign", corsMiddleware(handler.HandleAssignRole))
	mux.HandleFunc("/api/v1/iam/roles/revoke", corsMiddleware(handler.HandleRevokeRole))
	mux.HandleFunc("/api/v1/iam/users/", corsMiddleware(handler.HandleGetUserRoles))

	// Audit routes
	mux.HandleFunc("/api/v1/audit/logs", corsMiddleware(handler.HandleQueryAuditLogs))
	mux.HandleFunc("/api/v1/audit/activity", corsMiddleware(handler.HandleGetUserActivity))

	// Health check endpoint
	mux.HandleFunc("/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"service": "authentication-http",
		})
	}))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", httpPort),
		Handler: mux,
	}

	// Start server
	go func() {
		logger.Info("HTTP server listening", slog.String("service", "authentication-http"), slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down HTTP server")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	logger.Info("HTTP server stopped")
}
