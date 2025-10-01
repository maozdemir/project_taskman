package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	userPb "github.com/taskman/v2/services/user-service/pkg/api/api"
)

// HandleListUsers returns all users for the company
func (h *Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user info from context (set by auth middleware if implemented)
	// For now, we'll extract from JWT token in Authorization header
	token := extractTokenFromHeader(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
		return
	}

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		h.Logger.Error("invalid token", "error", err)
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid authorization token")
		return
	}

	// List users from User Service
	listReq := &userPb.ListUsersRequest{
		CompanyId: claims.CompanyID,
		Page:      1,
		PageSize:  100,
	}

	listResp, err := h.UserClient.Client.ListUsers(r.Context(), listReq)
	if err != nil {
		h.Logger.Error("failed to list users", "error", err)
		respondWithError(w, http.StatusInternalServerError, "LIST_FAILED", "Failed to list users")
		return
	}

	response := map[string]interface{}{
		"users":       listResp.Users,
		"total_count": listResp.TotalCount,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGetUser returns a specific user by ID
func (h *Handler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractTokenFromHeader(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
		return
	}

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid authorization token")
		return
	}

	// Extract user ID from URL path
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Missing user ID")
		return
	}
	userID := parts[4]

	getUserReq := &userPb.GetUserRequest{
		UserId:    userID,
		CompanyId: claims.CompanyID,
	}

	getUserResp, err := h.UserClient.Client.GetUser(r.Context(), getUserReq)
	if err != nil {
		h.Logger.Error("failed to get user", "error", err, "user_id", userID)
		respondWithError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	response := map[string]interface{}{
		"user": getUserResp.User,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleCreateUser creates a new user
func (h *Handler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractTokenFromHeader(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
		return
	}

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid authorization token")
		return
	}

	// Check authorization - only admins can create users
	if !hasRole(claims.Roles, "admin") {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Only administrators can create users")
		return
	}

	var req struct {
		Email      string `json:"email"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		FirstName  string `json:"first_name"`
		LastName   string `json:"last_name"`
		Department string `json:"department"`
		Location   string `json:"location"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	createUserReq := &userPb.CreateUserRequest{
		CompanyId:  claims.CompanyID,
		Email:      req.Email,
		Username:   req.Username,
		Password:   req.Password,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Department: req.Department,
		Location:   req.Location,
	}

	createUserResp, err := h.UserClient.Client.CreateUser(r.Context(), createUserReq)
	if err != nil {
		h.Logger.Error("failed to create user", "error", err)
		respondWithError(w, http.StatusInternalServerError, "CREATE_FAILED", "Failed to create user")
		return
	}

	response := map[string]interface{}{
		"user": createUserResp.User,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// HandleUpdateUser updates an existing user
func (h *Handler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractTokenFromHeader(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
		return
	}

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid authorization token")
		return
	}

	// Extract user ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Missing user ID")
		return
	}
	userID := parts[4]

	// Check authorization - admins can update anyone, users can only update themselves
	if !hasRole(claims.Roles, "admin") && claims.UserID != userID {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "You can only update your own profile")
		return
	}

	var req struct {
		Email      string `json:"email"`
		Username   string `json:"username"`
		FirstName  string `json:"first_name"`
		LastName   string `json:"last_name"`
		Department string `json:"department"`
		Location   string `json:"location"`
		IsActive   bool   `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	updateUserReq := &userPb.UpdateUserRequest{
		UserId:     userID,
		CompanyId:  claims.CompanyID,
		Email:      req.Email,
		Username:   req.Username,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Department: req.Department,
		Location:   req.Location,
		IsActive:   req.IsActive,
	}

	updateUserResp, err := h.UserClient.Client.UpdateUser(r.Context(), updateUserReq)
	if err != nil {
		h.Logger.Error("failed to update user", "error", err)
		respondWithError(w, http.StatusInternalServerError, "UPDATE_FAILED", "Failed to update user")
		return
	}

	response := map[string]interface{}{
		"user": updateUserResp.User,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleDeleteUser deletes a user
func (h *Handler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractTokenFromHeader(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
		return
	}

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid authorization token")
		return
	}

	// Extract user ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Missing user ID")
		return
	}
	userID := parts[4]

	// Check authorization - only admins can delete users
	if !hasRole(claims.Roles, "admin") {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Only administrators can delete users")
		return
	}

	deleteUserReq := &userPb.DeleteUserRequest{
		UserId:    userID,
		CompanyId: claims.CompanyID,
	}

	deleteUserResp, err := h.UserClient.Client.DeleteUser(r.Context(), deleteUserReq)
	if err != nil {
		h.Logger.Error("failed to delete user", "error", err)
		respondWithError(w, http.StatusInternalServerError, "DELETE_FAILED", "Failed to delete user")
		return
	}

	response := map[string]interface{}{
		"success": deleteUserResp.Success,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// extractTokenFromHeader extracts JWT token from Authorization header
func extractTokenFromHeader(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

// hasRole checks if the user has a specific role
func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
