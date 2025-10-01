package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/taskman/v2/services/authentication-service/internal/storage"
	userPb "github.com/taskman/v2/services/user-service/pkg/api/api"
	"github.com/taskman/v2/shared/pkg/idgen"
	"github.com/taskman/v2/shared/pkg/queue"
)

// HandleLogin processes user login requests
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.Error("failed to decode login request", "error", err)
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "INVALID_INPUT", "Email and password are required")
		return
	}

	h.Logger.Info("login attempt", "email", req.Email)

	// Extract IP address without port
	ipAddress := extractIPAddress(r.RemoteAddr)

	// Get user from User Service
	user, err := h.UserClient.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		h.Logger.Error("user lookup failed", "error", err, "email", req.Email)
		respondWithError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid credentials")
		h.recordFailedLogin(r.Context(), req.Email, ipAddress)
		return
	}

	// Check if user is active
	if !user.IsActive {
		h.Logger.Error("inactive user login attempt", "email", req.Email)
		respondWithError(w, http.StatusUnauthorized, "ACCOUNT_INACTIVE", "Account is inactive")
		h.recordFailedLogin(r.Context(), req.Email, ipAddress)
		return
	}

	// Verify password using User Service
	verifyReq := &userPb.VerifyPasswordRequest{
		UserId:    user.Id,
		CompanyId: user.CompanyId,
		Password:  req.Password,
	}
	verifyResp, err := h.UserClient.Client.VerifyPassword(r.Context(), verifyReq)
	if err != nil || !verifyResp.Valid {
		h.Logger.Error("password verification failed", "email", req.Email)
		respondWithError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid credentials")
		h.recordFailedLogin(r.Context(), req.Email, ipAddress)
		return
	}

	// Get user roles and permissions from IAM Admin Service
	rolesResp, err := h.IAMClient.GetUserRoles(r.Context(), user.Id, user.CompanyId)
	var roles []string
	if err != nil || rolesResp == nil || len(rolesResp.RoleNames) == 0 {
		h.Logger.Warn("failed to get user roles, using default", "user_id", user.Id, "error", err)
		roles = []string{"user"} // Default role
	} else {
		roles = rolesResp.RoleNames
	}

	// Get user permissions
	permissionsResp, err := h.IAMClient.GetUserPermissions(r.Context(), user.Id, user.CompanyId)
	var permissions []string
	if err != nil || permissionsResp == nil || len(permissionsResp.Permissions) == 0 {
		h.Logger.Warn("failed to get user permissions, using empty", "user_id", user.Id, "error", err)
		permissions = []string{} // No permissions by default
	} else {
		permissions = permissionsResp.Permissions
	}

	// Generate session ID and tokens
	sessionID := storage.GenerateSessionID()

	// Use actual company_id from user
	companyID := user.CompanyId
	if companyID == "" {
		h.Logger.Error("user has no company_id", "user_id", user.Id, "email", user.Email)
		respondWithError(w, http.StatusInternalServerError, "INVALID_USER_DATA", "User account is not properly configured")
		return
	}

	tokenPair, err := h.JWTManager.GenerateTokenPair(
		user.Id,
		user.Email,
		user.Username,
		companyID,
		roles,
		permissions,
		sessionID,
	)
	if err != nil {
		h.Logger.Error("failed to generate tokens", "error", err)
		respondWithError(w, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "Failed to generate tokens")
		return
	}

	// Create session
	session := &storage.Session{
		ID:           sessionID,
		UserID:       user.Id,
		RefreshToken: tokenPair.RefreshToken,
		IPAddress:    ipAddress,
		UserAgent:    r.UserAgent(),
		ExpiresAt:    tokenPair.ExpiresAt.Add(7 * 24 * time.Hour),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
	}

	if err := h.Storage.CreateSession(r.Context(), session); err != nil {
		h.Logger.Error("failed to create session", "error", err)
		// Continue anyway, session failure shouldn't block login
	}

	// Record successful login
	h.recordSuccessfulLogin(r.Context(), req.Email, ipAddress)

	// Publish login event
	if h.Queue != nil {
		event := &queue.Event{
			ID:        idgen.GenerateID(),
			Type:      "auth.login.success",
			Timestamp: time.Now(),
			Payload: map[string]interface{}{
				"user_id":    user.Id,
				"company_id": companyID,
				"email":      req.Email,
				"ip_address": ipAddress,
			},
		}
		if err := h.Queue.Publish(r.Context(), "auth.login.success", event); err != nil {
			h.Logger.Warn("failed to publish login event", "error", err)
		}
	}

	response := AuthResponse{
		Success: true,
		Data: map[string]interface{}{
			"user": map[string]interface{}{
				"id":          user.Id,
				"username":    user.Username,
				"email":       user.Email,
				"first_name":  user.FirstName,
				"last_name":   user.LastName,
				"company_id":  companyID,
				"roles":       roles,
				"permissions": permissions,
			},
			"token":        tokenPair.AccessToken,
			"refreshToken": tokenPair.RefreshToken,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	h.Logger.Info("login successful", "email", req.Email, "user_id", user.Id, "company_id", companyID)
}
