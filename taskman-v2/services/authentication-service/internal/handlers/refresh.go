package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/taskman/v2/services/authentication-service/internal/storage"
)

// HandleRefresh processes token refresh requests
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.Error("failed to decode refresh request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	h.Logger.Info("token refresh attempt")

	// Verify refresh token
	claims, err := h.JWTManager.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		h.Logger.Error("invalid refresh token", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid refresh token"})
		return
	}

	// Get user from User Service to ensure they still exist and are active
	user, err := h.UserClient.GetUserByEmail(r.Context(), claims.Email)
	if err != nil {
		h.Logger.Error("user lookup failed during refresh", "error", err)
		respondWithError(w, http.StatusUnauthorized, "USER_NOT_FOUND", "User not found")
		return
	}

	if !user.IsActive {
		h.Logger.Error("inactive user refresh attempt", "email", claims.Email)
		respondWithError(w, http.StatusUnauthorized, "ACCOUNT_INACTIVE", "Account is inactive")
		return
	}

	// Get user roles and permissions from IAM Service
	rolesResp, err := h.IAMClient.GetUserRoles(r.Context(), user.Id, user.CompanyId)
	var roles []string
	if err != nil || rolesResp == nil || len(rolesResp.RoleNames) == 0 {
		h.Logger.Warn("failed to get user roles, using default", "user_id", user.Id, "error", err)
		roles = []string{"user"}
	} else {
		roles = rolesResp.RoleNames
	}

	// Get user permissions
	permissionsResp, err := h.IAMClient.GetUserPermissions(r.Context(), user.Id, user.CompanyId)
	var permissions []string
	if err != nil || permissionsResp == nil || len(permissionsResp.Permissions) == 0 {
		h.Logger.Warn("failed to get user permissions, using empty", "user_id", user.Id, "error", err)
		permissions = []string{}
	} else {
		permissions = permissionsResp.Permissions
	}

	// Generate new tokens
	sessionID := storage.GenerateSessionID()
	tokenPair, err := h.JWTManager.GenerateTokenPair(
		user.Id,
		user.Email,
		user.Username,
		user.CompanyId,
		roles,
		permissions,
		sessionID,
	)
	if err != nil {
		h.Logger.Error("failed to generate tokens", "error", err)
		respondWithError(w, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "Failed to generate tokens")
		return
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
				"company_id":  user.CompanyId,
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
	h.Logger.Info("token refresh successful", "user_id", user.Id, "company_id", user.CompanyId)
}
