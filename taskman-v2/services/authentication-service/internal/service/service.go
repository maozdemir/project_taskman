package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	pb "github.com/taskman/v2/services/authentication-service/pkg/api/api"
	"github.com/taskman/v2/services/authentication-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/queue"
	"github.com/taskman/v2/shared/pkg/validation"
	"google.golang.org/protobuf/types/known/timestamppb"
	"golang.org/x/crypto/bcrypt"
)

// Service implements the AuthenticationService
type Service struct {
	pb.UnimplementedAuthenticationServiceServer
	storage    *storage.Storage
	cache      *cache.Cache
	queue      *queue.Queue
	jwtManager *jwt.Manager
	log        *logger.Logger
}

// Config holds service configuration
type Config struct {
	Storage    *storage.Storage
	Cache      *cache.Cache
	Queue      *queue.Queue
	JWTManager *jwt.Manager
	Logger     *logger.Logger
}

// New creates a new Service
func New(cfg *Config) *Service {
	return &Service{
		storage:    cfg.Storage,
		cache:      cfg.Cache,
		queue:      cfg.Queue,
		jwtManager: cfg.JWTManager,
		log:        cfg.Logger,
	}
}

// Login authenticates a user and returns JWT tokens
func (s *Service) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Validate input
	v := validation.New()
	v.Required("email", req.Email)
	v.Email("email", req.Email)
	v.Required("password", req.Password)

	if v.HasErrors() {
		err := v.FirstError()
		return nil, errors.InvalidArgument(err.Field, err.Message).ToGRPCError()
	}

	// Check rate limiting
	since := time.Now().Add(-15 * time.Minute)
	attempts, err := s.storage.GetRecentLoginAttempts(ctx, req.Email, since)
	if err != nil {
		s.log.Error("failed to check login attempts", "error", err)
	}

	if attempts >= 5 {
		return nil, errors.ResourceExhausted("too many login attempts, please try again later").ToGRPCError()
	}

	// TODO: Call user-service to get user details and verify password
	// For now, we'll simulate this
	// In real implementation: userClient.GetUserByEmail(ctx, req.Email)
	// and verify password with bcrypt.CompareHashAndPassword

	// Simulated user data (replace with actual user-service call)
	userID := uuid.New().String()
	companyID := uuid.New().String()
	roles := []string{"user"}

	// Generate session ID and tokens
	sessionID := storage.GenerateSessionID()
	tokenPair, err := s.jwtManager.GenerateTokenPair(
		userID,
		req.Email,
		req.Email, // username
		companyID,
		roles,
		sessionID,
	)
	if err != nil {
		s.log.Error("failed to generate tokens", "error", err)
		return nil, errors.Internal("failed to generate tokens").ToGRPCError()
	}

	// Create session
	session := &storage.Session{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: tokenPair.RefreshToken,
		IPAddress:    req.IpAddress,
		UserAgent:    req.UserAgent,
		ExpiresAt:    tokenPair.ExpiresAt.Add(7 * 24 * time.Hour), // Refresh token expires in 7 days
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
	}

	if err := s.storage.CreateSession(ctx, session); err != nil {
		s.log.Error("failed to create session", "error", err)
		return nil, errors.Internal("failed to create session").ToGRPCError()
	}

	// Store session in Redis cache
	cacheKey := fmt.Sprintf("session:%s", sessionID)
	if err := s.cache.Set(ctx, cacheKey, session.ID, 7*24*time.Hour); err != nil {
		s.log.Warn("failed to cache session", "error", err)
	}

	// Record successful login attempt
	attempt := &storage.LoginAttempt{
		ID:        uuid.New().String(),
		Email:     req.Email,
		IPAddress: req.IpAddress,
		Success:   true,
		CreatedAt: time.Now(),
	}
	if err := s.storage.RecordLoginAttempt(ctx, attempt); err != nil {
		s.log.Warn("failed to record login attempt", "error", err)
	}

	// Publish login success event
	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "auth.login.success",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"user_id":    userID,
			"email":      req.Email,
			"ip_address": req.IpAddress,
			"session_id": sessionID,
		},
	}
	if err := s.queue.Publish(ctx, "auth.login.success", event); err != nil {
		s.log.Warn("failed to publish login event", "error", err)
	}

	return &pb.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
		User: &pb.User{
			Id:        userID,
			Email:     req.Email,
			Username:  req.Email,
			CompanyId: companyID,
			Roles:     roles,
		},
	}, nil
}

// Logout invalidates the user's session
func (s *Service) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	// Validate input
	if req.SessionId == "" {
		return nil, errors.InvalidArgument("session_id", "is required").ToGRPCError()
	}

	// Revoke session
	if err := s.storage.RevokeSession(ctx, req.SessionId); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr.Code.String() == "NotFound" {
			return &pb.LogoutResponse{Success: false}, nil
		}
		s.log.Error("failed to revoke session", "error", err)
		return nil, errors.Internal("failed to logout").ToGRPCError()
	}

	// Remove from cache
	cacheKey := fmt.Sprintf("session:%s", req.SessionId)
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.log.Warn("failed to delete session from cache", "error", err)
	}

	// Publish logout event
	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "auth.logout",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"session_id": req.SessionId,
		},
	}
	if err := s.queue.Publish(ctx, "auth.logout", event); err != nil {
		s.log.Warn("failed to publish logout event", "error", err)
	}

	return &pb.LogoutResponse{Success: true}, nil
}

// RefreshToken generates a new access token using a refresh token
func (s *Service) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	// Validate input
	if req.RefreshToken == "" {
		return nil, errors.InvalidArgument("refresh_token", "is required").ToGRPCError()
	}

	// Verify refresh token
	claims, err := s.jwtManager.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		s.log.Warn("invalid refresh token", "error", err)
		return nil, errors.Unauthenticated("invalid refresh token").ToGRPCError()
	}

	// Get session from database
	session, err := s.storage.GetSessionByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		s.log.Error("failed to get session", "error", err)
		return nil, errors.Unauthenticated("invalid refresh token").ToGRPCError()
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, errors.Unauthenticated("session expired").ToGRPCError()
	}

	// Generate new token pair
	tokenPair, err := s.jwtManager.GenerateTokenPair(
		claims.UserID,
		claims.Email,
		claims.Username,
		claims.CompanyID,
		claims.Roles,
		session.ID,
	)
	if err != nil {
		s.log.Error("failed to generate tokens", "error", err)
		return nil, errors.Internal("failed to generate tokens").ToGRPCError()
	}

	// Publish token refresh event
	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      "auth.token.refreshed",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"user_id":    claims.UserID,
			"session_id": session.ID,
		},
	}
	if err := s.queue.Publish(ctx, "auth.token.refreshed", event); err != nil {
		s.log.Warn("failed to publish token refresh event", "error", err)
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}

// VerifyToken validates a JWT token
func (s *Service) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	// Validate input
	if req.Token == "" {
		return nil, errors.InvalidArgument("token", "is required").ToGRPCError()
	}

	// Verify access token
	claims, err := s.jwtManager.VerifyAccessToken(req.Token)
	if err != nil {
		return &pb.VerifyTokenResponse{Valid: false}, nil
	}

	return &pb.VerifyTokenResponse{
		Valid: true,
		Claims: &pb.TokenClaims{
			UserId:    claims.UserID,
			Email:     claims.Email,
			Username:  claims.Username,
			CompanyId: claims.CompanyID,
			Roles:     claims.Roles,
			IssuedAt:  timestamppb.New(time.Unix(claims.IssuedAt, 0)),
			ExpiresAt: timestamppb.New(time.Unix(claims.ExpiresAt, 0)),
		},
	}, nil
}

// GetSession retrieves session information
func (s *Service) GetSession(ctx context.Context, req *pb.GetSessionRequest) (*pb.GetSessionResponse, error) {
	// Validate input
	if req.SessionId == "" {
		return nil, errors.InvalidArgument("session_id", "is required").ToGRPCError()
	}

	// Try to get from cache first
	cacheKey := fmt.Sprintf("session:%s", req.SessionId)
	if _, err := s.cache.Get(ctx, cacheKey); err == nil {
		// Cache hit - get from database
		session, err := s.storage.GetSession(ctx, req.SessionId)
		if err != nil {
			return nil, err.(*errors.AppError).ToGRPCError()
		}

		return &pb.GetSessionResponse{
			Session: &pb.Session{
				Id:        session.ID,
				UserId:    session.UserID,
				IpAddress: session.IPAddress,
				UserAgent: session.UserAgent,
				CreatedAt: timestamppb.New(session.CreatedAt),
				ExpiresAt: timestamppb.New(session.ExpiresAt),
				IsActive:  session.IsActive,
			},
		}, nil
	}

	// Not in cache - get from database
	session, err := s.storage.GetSession(ctx, req.SessionId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Cache for next time
	if err := s.cache.Set(ctx, cacheKey, session.ID, 1*time.Hour); err != nil {
		s.log.Warn("failed to cache session", "error", err)
	}

	return &pb.GetSessionResponse{
		Session: &pb.Session{
			Id:        session.ID,
			UserId:    session.UserID,
			IpAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			CreatedAt: timestamppb.New(session.CreatedAt),
			ExpiresAt: timestamppb.New(session.ExpiresAt),
			IsActive:  session.IsActive,
		},
	}, nil
}

// ListSessions lists all active sessions for a user
func (s *Service) ListSessions(ctx context.Context, req *pb.ListSessionsRequest) (*pb.ListSessionsResponse, error) {
	// Validate input
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}

	// Get sessions from database
	sessions, err := s.storage.ListSessionsByUserID(ctx, req.UserId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Convert to protobuf
	pbSessions := make([]*pb.Session, 0, len(sessions))
	for _, session := range sessions {
		pbSessions = append(pbSessions, &pb.Session{
			Id:        session.ID,
			UserId:    session.UserID,
			IpAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			CreatedAt: timestamppb.New(session.CreatedAt),
			ExpiresAt: timestamppb.New(session.ExpiresAt),
			IsActive:  session.IsActive,
		})
	}

	return &pb.ListSessionsResponse{
		Sessions: pbSessions,
	}, nil
}

// RevokeSession revokes a specific session
func (s *Service) RevokeSession(ctx context.Context, req *pb.RevokeSessionRequest) (*pb.RevokeSessionResponse, error) {
	// Validate input
	if req.SessionId == "" {
		return nil, errors.InvalidArgument("session_id", "is required").ToGRPCError()
	}

	// Revoke session
	if err := s.storage.RevokeSession(ctx, req.SessionId); err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Remove from cache
	cacheKey := fmt.Sprintf("session:%s", req.SessionId)
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.log.Warn("failed to delete session from cache", "error", err)
	}

	return &pb.RevokeSessionResponse{Success: true}, nil
}

// InitiatePasswordReset sends a password reset email
func (s *Service) InitiatePasswordReset(ctx context.Context, req *pb.PasswordResetRequest) (*pb.PasswordResetResponse, error) {
	// TODO: Implement password reset logic
	// This would involve:
	// 1. Validate email
	// 2. Create password reset token
	// 3. Send email via notification service
	return &pb.PasswordResetResponse{
		Success: true,
		Message: "Password reset email sent (not implemented yet)",
	}, nil
}

// CompletePasswordReset resets the password using a reset token
func (s *Service) CompletePasswordReset(ctx context.Context, req *pb.CompletePasswordResetRequest) (*pb.CompletePasswordResetResponse, error) {
	// TODO: Implement password reset completion
	return &pb.CompletePasswordResetResponse{Success: true}, nil
}

// HealthCheck checks service health
func (s *Service) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Status:    "healthy",
		Timestamp: timestamppb.Now(),
	}, nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// VerifyPassword checks if a password matches a hash
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}