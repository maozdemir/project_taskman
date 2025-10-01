package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

// HandleMe processes current user info requests
func (h *Handler) HandleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract JWT from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, http.StatusUnauthorized, "MISSING_AUTH", "Authorization header required")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		respondWithError(w, http.StatusUnauthorized, "INVALID_AUTH_FORMAT", "Authorization header must be 'Bearer <token>'")
		return
	}

	token := parts[1]
	h.Logger.Info("get current user attempt")

	// Verify access token
	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		h.Logger.Error("token validation failed", "error", err)
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token")
		return
	}

	// Get full user info from User Service
	user, err := h.UserClient.GetUserByEmail(r.Context(), claims.Email)
	if err != nil {
		h.Logger.Error("user lookup failed", "error", err, "user_id", claims.UserID)
		respondWithError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	if !user.IsActive {
		h.Logger.Error("inactive user accessed /me", "user_id", user.Id)
		respondWithError(w, http.StatusForbidden, "ACCOUNT_INACTIVE", "Account is inactive")
		return
	}

	// Get current roles from IAM Service
	rolesResp, err := h.IAMClient.GetUserRoles(r.Context(), user.Id, user.CompanyId)
	var roles []string
	if err != nil || rolesResp == nil || len(rolesResp.RoleNames) == 0 {
		h.Logger.Warn("failed to get user roles for /me", "user_id", user.Id, "error", err)
		roles = claims.Roles // Fallback to JWT claims
	} else {
		roles = rolesResp.RoleNames
	}

	response := AuthResponse{
		Success: true,
		Data: map[string]interface{}{
			"id":         user.Id,
			"username":   user.Username,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"company_id": user.CompanyId,
			"roles":      roles,
			"is_active":  user.IsActive,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	h.Logger.Info("get current user successful", "user_id", user.Id, "company_id", user.CompanyId)
}
