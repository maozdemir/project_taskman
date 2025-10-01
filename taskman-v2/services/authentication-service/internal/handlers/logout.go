package handlers

import (
	"encoding/json"
	"net/http"
)

// HandleLogout processes user logout requests
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.Error("failed to decode logout request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	h.Logger.Info("logout attempt")

	// Invalidate session by refresh token
	session, err := h.Storage.GetSessionByRefreshToken(r.Context(), req.RefreshToken)
	if err == nil && session != nil {
		if err := h.Storage.RevokeSession(r.Context(), session.ID); err != nil {
			h.Logger.Warn("failed to revoke session", "error", err)
		}
	}

	response := AuthResponse{
		Success: true,
		Message: "Logged out successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	h.Logger.Info("logout successful")
}
