package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/taskman/v2/services/authentication-service/internal/storage"
	userPb "github.com/taskman/v2/services/user-service/pkg/api/api"
)

// HandleRegister processes user registration requests
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.Error("failed to decode register request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	h.Logger.Info("registration attempt", "email", req.Email, "username", req.Username)

	// Check if user exists using User Service
	existing, _ := h.UserClient.GetUserByEmail(r.Context(), req.Email)
	if existing != nil {
		h.Logger.Error("user already exists", "email", req.Email)
		respondWithError(w, http.StatusBadRequest, "USER_EXISTS", "User already exists")
		return
	}

	// Create user via User Service
	createUserReq := &userPb.CreateUserRequest{
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	createUserResp, err := h.UserClient.Client.CreateUser(r.Context(), createUserReq)
	if err != nil {
		h.Logger.Error("failed to create user", "error", err)
		respondWithError(w, http.StatusInternalServerError, "USER_CREATION_FAILED", "Failed to create user")
		return
	}

	userID := createUserResp.User.Id
	companyID := createUserResp.User.CompanyId

	// Get initial user roles and permissions from IAM Service
	rolesResp, err := h.IAMClient.GetUserRoles(r.Context(), userID, companyID)
	var roles []string
	if err != nil || rolesResp == nil || len(rolesResp.RoleNames) == 0 {
		h.Logger.Warn("failed to get user roles, using default", "user_id", userID, "error", err)
		roles = []string{"user"}
	} else {
		roles = rolesResp.RoleNames
	}

	// Get user permissions
	permissionsResp, err := h.IAMClient.GetUserPermissions(r.Context(), userID, companyID)
	var permissions []string
	if err != nil || permissionsResp == nil || len(permissionsResp.Permissions) == 0 {
		h.Logger.Warn("failed to get user permissions, using empty", "user_id", userID, "error", err)
		permissions = []string{}
	} else {
		permissions = permissionsResp.Permissions
	}

	// Generate session and tokens
	sessionID := storage.GenerateSessionID()

	tokenPair, err := h.JWTManager.GenerateTokenPair(
		userID,
		req.Email,
		req.Username,
		companyID,
		roles,
		permissions,
		sessionID,
	)
	if err != nil {
		h.Logger.Error("failed to generate tokens", "error", err)
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

	if err := h.Storage.CreateSession(r.Context(), session); err != nil {
		h.Logger.Warn("failed to create session", "error", err)
	}

	response := AuthResponse{
		Success: true,
		Data: map[string]interface{}{
			"user": map[string]interface{}{
				"id":          userID,
				"username":    createUserResp.User.Username,
				"email":       createUserResp.User.Email,
				"first_name":  createUserResp.User.FirstName,
				"last_name":   createUserResp.User.LastName,
				"company_id":  companyID,
				"roles":       roles,
				"permissions": permissions,
			},
			"token":        tokenPair.AccessToken,
			"refreshToken": tokenPair.RefreshToken,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
	h.Logger.Info("registration successful", "email", req.Email, "user_id", userID, "company_id", companyID)
}
