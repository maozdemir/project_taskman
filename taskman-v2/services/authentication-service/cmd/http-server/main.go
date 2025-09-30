package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/taskman/v2/services/authentication-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/queue"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

var logger *slog.Logger

type HTTPServer struct {
	db         *database.DB
	cache      *cache.Cache
	queue      *queue.Queue
	jwtManager *jwt.Manager
	storage    *storage.Storage
}

type User struct {
	ID           string
	Email        string
	Username     string
	PasswordHash string
	FirstName    string
	LastName     string
	IsActive     bool
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type AuthResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

func (s *HTTPServer) getUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `SELECT id, email, username, password_hash, first_name, last_name, is_active FROM users WHERE email = $1`

	var user User
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *HTTPServer) getUserRoles(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return []string{}, nil // Return empty array if no roles table
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return []string{}, err
		}
		roles = append(roles, role)
	}

	if len(roles) == 0 {
		roles = []string{"user"} // Default role
	}

	return roles, nil
}

func (s *HTTPServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("failed to decode login request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	logger.Info("login attempt", "email", req.Email)

	// Get user from database
	user, err := s.getUserByEmail(r.Context(), req.Email)
	if err != nil {
		logger.Error("user lookup failed", "error", err, "email", req.Email)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid credentials"})
		return
	}

	// Check if user is active
	if !user.IsActive {
		logger.Error("inactive user login attempt", "email", req.Email)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Account is inactive"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		logger.Error("password verification failed", "email", req.Email)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid credentials"})
		return
	}

	// Get user roles
	roles, err := s.getUserRoles(r.Context(), user.ID)
	if err != nil {
		logger.Error("failed to get user roles", "error", err)
		roles = []string{"user"}
	}

	// Generate session ID and tokens
	sessionID := storage.GenerateSessionID()
	companyID := uuid.New().String() // TODO: Get actual company ID from user

	tokenPair, err := s.jwtManager.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Username,
		companyID,
		roles,
		sessionID,
	)
	if err != nil {
		logger.Error("failed to generate tokens", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to generate tokens"})
		return
	}

	// Create session
	session := &storage.Session{
		ID:           sessionID,
		UserID:       user.ID,
		RefreshToken: tokenPair.RefreshToken,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
	}

	if err := s.storage.CreateSession(r.Context(), session); err != nil {
		logger.Error("failed to create session", "error", err)
		// Continue anyway, session failure shouldn't block login
	}

	// Record successful login
	attempt := &storage.LoginAttempt{
		ID:        uuid.New().String(),
		Email:     req.Email,
		IPAddress: r.RemoteAddr,
		Success:   true,
		CreatedAt: time.Now(),
	}
	if err := s.storage.RecordLoginAttempt(r.Context(), attempt); err != nil {
		logger.Warn("failed to record login attempt", "error", err)
	}

	response := AuthResponse{
		Success: true,
		Data: map[string]interface{}{
			"user": map[string]interface{}{
				"id":         user.ID,
				"username":   user.Username,
				"email":      user.Email,
				"first_name": user.FirstName,
				"last_name":  user.LastName,
				"roles":      roles,
			},
			"token":        tokenPair.AccessToken,
			"refreshToken": tokenPair.RefreshToken,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	logger.Info("login successful", "email", req.Email, "user_id", user.ID)
}

func (s *HTTPServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("failed to decode register request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	logger.Info("registration attempt", "email", req.Email, "username", req.Username)

	// Check if user exists
	existing, _ := s.getUserByEmail(r.Context(), req.Email)
	if existing != nil {
		logger.Error("user already exists", "email", req.Email)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "User already exists"})
		return
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("failed to hash password", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to process password"})
		return
	}

	// Create user
	query := `
		INSERT INTO users (email, username, password_hash, first_name, last_name, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
		RETURNING id
	`

	var userID string
	err = s.db.QueryRowContext(r.Context(), query, req.Email, req.Username, string(passwordHash), req.FirstName, req.LastName).Scan(&userID)
	if err != nil {
		logger.Error("failed to create user", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to create user"})
		return
	}

	// Generate tokens
	sessionID := storage.GenerateSessionID()
	companyID := uuid.New().String()
	roles := []string{"user"}

	tokenPair, err := s.jwtManager.GenerateTokenPair(
		userID,
		req.Email,
		req.Username,
		companyID,
		roles,
		sessionID,
	)
	if err != nil {
		logger.Error("failed to generate tokens", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to generate tokens"})
		return
	}

	// Create session
	session := &storage.Session{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: tokenPair.RefreshToken,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
	}

	if err := s.storage.CreateSession(r.Context(), session); err != nil {
		logger.Warn("failed to create session", "error", err)
	}

	response := AuthResponse{
		Success: true,
		Data: map[string]interface{}{
			"user": map[string]interface{}{
				"id":         userID,
				"username":   req.Username,
				"email":      req.Email,
				"first_name": req.FirstName,
				"last_name":  req.LastName,
				"roles":      roles,
			},
			"token":        tokenPair.AccessToken,
			"refreshToken": tokenPair.RefreshToken,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
	logger.Info("registration successful", "email", req.Email, "user_id", userID)
}

func (s *HTTPServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("failed to decode refresh request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	logger.Info("token refresh attempt")

	// Verify refresh token
	claims, err := s.jwtManager.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		logger.Error("invalid refresh token", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid refresh token"})
		return
	}

	// Get user to ensure they still exist and are active
	user, err := s.getUserByEmail(r.Context(), claims.Email)
	if err != nil {
		logger.Error("user lookup failed during refresh", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "User not found"})
		return
	}

	if !user.IsActive {
		logger.Error("inactive user refresh attempt", "email", claims.Email)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Account is inactive"})
		return
	}

	// Get user roles
	roles, err := s.getUserRoles(r.Context(), user.ID)
	if err != nil {
		logger.Error("failed to get user roles", "error", err)
		roles = []string{"user"}
	}

	// Generate new tokens
	sessionID := storage.GenerateSessionID()
	tokenPair, err := s.jwtManager.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Username,
		claims.CompanyID,
		roles,
		sessionID,
	)
	if err != nil {
		logger.Error("failed to generate tokens", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to generate tokens"})
		return
	}

	response := AuthResponse{
		Success: true,
		Data: map[string]interface{}{
			"user": map[string]interface{}{
				"id":       user.ID,
				"username": user.Username,
				"email":    user.Email,
			},
			"token":        tokenPair.AccessToken,
			"refreshToken": tokenPair.RefreshToken,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	logger.Info("token refresh successful", "user_id", user.ID)
}

func (s *HTTPServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("failed to decode logout request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	logger.Info("logout attempt")

	// Invalidate session by refresh token
	session, err := s.storage.GetSessionByRefreshToken(r.Context(), req.RefreshToken)
	if err == nil && session != nil {
		if err := s.storage.RevokeSession(r.Context(), session.ID); err != nil {
			logger.Warn("failed to revoke session", "error", err)
		}
	}

	response := AuthResponse{
		Success: true,
		Message: "Logged out successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	logger.Info("logout successful")
}

func (s *HTTPServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing authorization header"})
		return
	}

	// Remove "Bearer " prefix
	token := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	logger.Info("token validation attempt")

	claims, err := s.jwtManager.VerifyAccessToken(token)
	if err != nil {
		logger.Error("token validation failed", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid token"})
		return
	}

	response := AuthResponse{
		Success: true,
		Data: map[string]interface{}{
			"sub":        claims.UserID,
			"email":      claims.Email,
			"roles":      claims.Roles,
			"company_id": claims.CompanyID,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	logger.Info("token validation successful", "user_id", claims.UserID)
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
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

	// Initialize HTTP server
	httpServer := &HTTPServer{
		db:         db,
		cache:      cacheClient,
		queue:      queueClient,
		jwtManager: jwtManager,
		storage:    storageInst,
	}

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", corsMiddleware(httpServer.handleLogin))
	mux.HandleFunc("/api/v1/auth/register", corsMiddleware(httpServer.handleRegister))
	mux.HandleFunc("/api/v1/auth/refresh", corsMiddleware(httpServer.handleRefresh))
	mux.HandleFunc("/api/v1/auth/logout", corsMiddleware(httpServer.handleLogout))
	mux.HandleFunc("/api/v1/auth/validate", corsMiddleware(httpServer.handleValidate))

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