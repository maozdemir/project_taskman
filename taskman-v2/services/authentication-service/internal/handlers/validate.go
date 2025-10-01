package handlers

import (
	"encoding/json"
	"net/http"
)

// HandleValidate processes token validation requests
func (h *Handler) HandleValidate(w http.ResponseWriter, r *http.Request) {
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

	h.Logger.Info("token validation attempt")

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		h.Logger.Error("token validation failed", "error", err)
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
	h.Logger.Info("token validation successful", "user_id", claims.UserID)
}
