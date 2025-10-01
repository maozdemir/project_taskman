package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	iamPb "github.com/taskman/v2/services/iam-admin-service/pkg/api/api"
)

// HandleListRoles returns all roles for the company
func (h *Handler) HandleListRoles(w http.ResponseWriter, r *http.Request) {
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

	listReq := &iamPb.ListRolesRequest{
		CompanyId:          claims.CompanyID,
		IncludeSystemRoles: true,
	}

	listResp, err := h.IAMClient.Client.ListRoles(r.Context(), listReq)
	if err != nil {
		h.Logger.Error("failed to list roles", "error", err)
		respondWithError(w, http.StatusInternalServerError, "LIST_FAILED", "Failed to list roles")
		return
	}

	response := map[string]interface{}{
		"roles": listResp.Roles,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGetRole returns a specific role by ID
func (h *Handler) HandleGetRole(w http.ResponseWriter, r *http.Request) {
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

	// Extract role ID from URL path
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Missing role ID")
		return
	}
	roleID := parts[5]

	getRoleReq := &iamPb.GetRoleRequest{
		RoleId:    roleID,
		CompanyId: claims.CompanyID,
	}

	getRoleResp, err := h.IAMClient.Client.GetRole(r.Context(), getRoleReq)
	if err != nil {
		h.Logger.Error("failed to get role", "error", err, "role_id", roleID)
		respondWithError(w, http.StatusNotFound, "ROLE_NOT_FOUND", "Role not found")
		return
	}

	response := map[string]interface{}{
		"role": getRoleResp.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleCreateRole creates a new role
func (h *Handler) HandleCreateRole(w http.ResponseWriter, r *http.Request) {
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

	// Check authorization - only admins can create roles
	if !hasRole(claims.Roles, "admin") {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Only administrators can create roles")
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
		Priority    int32    `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	// Default priority if not provided
	if req.Priority == 0 {
		req.Priority = 50
	}

	createRoleReq := &iamPb.CreateRoleRequest{
		CompanyId:   claims.CompanyID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		Priority:    req.Priority,
	}

	createRoleResp, err := h.IAMClient.Client.CreateRole(r.Context(), createRoleReq)
	if err != nil {
		h.Logger.Error("failed to create role", "error", err)
		respondWithError(w, http.StatusInternalServerError, "CREATE_FAILED", "Failed to create role")
		return
	}

	response := map[string]interface{}{
		"role": createRoleResp.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// HandleUpdateRole updates an existing role
func (h *Handler) HandleUpdateRole(w http.ResponseWriter, r *http.Request) {
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

	// Check authorization - only admins can update roles
	if !hasRole(claims.Roles, "admin") {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Only administrators can update roles")
		return
	}

	// Extract role ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Missing role ID")
		return
	}
	roleID := parts[5]

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
		Priority    int32    `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	updateRoleReq := &iamPb.UpdateRoleRequest{
		RoleId:      roleID,
		CompanyId:   claims.CompanyID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		Priority:    req.Priority,
	}

	updateRoleResp, err := h.IAMClient.Client.UpdateRole(r.Context(), updateRoleReq)
	if err != nil {
		h.Logger.Error("failed to update role", "error", err)
		respondWithError(w, http.StatusInternalServerError, "UPDATE_FAILED", "Failed to update role")
		return
	}

	response := map[string]interface{}{
		"role": updateRoleResp.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleDeleteRole deletes a role
func (h *Handler) HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
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

	// Check authorization - only admins can delete roles
	if !hasRole(claims.Roles, "admin") {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Only administrators can delete roles")
		return
	}

	// Extract role ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Missing role ID")
		return
	}
	roleID := parts[5]

	deleteRoleReq := &iamPb.DeleteRoleRequest{
		RoleId:    roleID,
		CompanyId: claims.CompanyID,
	}

	deleteRoleResp, err := h.IAMClient.Client.DeleteRole(r.Context(), deleteRoleReq)
	if err != nil {
		h.Logger.Error("failed to delete role", "error", err)
		respondWithError(w, http.StatusInternalServerError, "DELETE_FAILED", "Failed to delete role")
		return
	}

	response := map[string]interface{}{
		"success": deleteRoleResp.Success,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleAssignRole assigns a role to a user
func (h *Handler) HandleAssignRole(w http.ResponseWriter, r *http.Request) {
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

	// Check authorization - only admins can assign roles
	if !hasRole(claims.Roles, "admin") {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Only administrators can assign roles")
		return
	}

	var req struct {
		UserID string `json:"user_id"`
		RoleID string `json:"role_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	assignRoleReq := &iamPb.AssignRoleRequest{
		UserId:     req.UserID,
		RoleId:     req.RoleID,
		CompanyId:  claims.CompanyID,
		AssignedBy: claims.UserID,
	}

	assignRoleResp, err := h.IAMClient.Client.AssignRole(r.Context(), assignRoleReq)
	if err != nil {
		h.Logger.Error("failed to assign role", "error", err)
		respondWithError(w, http.StatusInternalServerError, "ASSIGN_FAILED", "Failed to assign role")
		return
	}

	response := map[string]interface{}{
		"user_role": assignRoleResp.UserRole,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleRevokeRole revokes a role from a user
func (h *Handler) HandleRevokeRole(w http.ResponseWriter, r *http.Request) {
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

	// Check authorization - only admins can revoke roles
	if !hasRole(claims.Roles, "admin") {
		respondWithError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Only administrators can revoke roles")
		return
	}

	var req struct {
		UserID string `json:"user_id"`
		RoleID string `json:"role_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	revokeRoleReq := &iamPb.RevokeRoleRequest{
		UserId:    req.UserID,
		RoleId:    req.RoleID,
		CompanyId: claims.CompanyID,
	}

	revokeRoleResp, err := h.IAMClient.Client.RevokeRole(r.Context(), revokeRoleReq)
	if err != nil {
		h.Logger.Error("failed to revoke role", "error", err)
		respondWithError(w, http.StatusInternalServerError, "REVOKE_FAILED", "Failed to revoke role")
		return
	}

	response := map[string]interface{}{
		"success": revokeRoleResp.Success,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGetUserRoles returns roles assigned to a user
func (h *Handler) HandleGetUserRoles(w http.ResponseWriter, r *http.Request) {
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
	if len(parts) < 6 {
		respondWithError(w, http.StatusBadRequest, "INVALID_REQUEST", "Missing user ID")
		return
	}
	userID := parts[4]

	getUserRolesReq := &iamPb.GetUserRolesRequest{
		UserId:    userID,
		CompanyId: claims.CompanyID,
	}

	getUserRolesResp, err := h.IAMClient.Client.GetUserRoles(r.Context(), getUserRolesReq)
	if err != nil {
		h.Logger.Error("failed to get user roles", "error", err, "user_id", userID)
		respondWithError(w, http.StatusInternalServerError, "GET_ROLES_FAILED", "Failed to get user roles")
		return
	}

	response := map[string]interface{}{
		"roles":           getUserRolesResp.Roles,
		"role_names":      getUserRolesResp.RoleNames,
		"all_permissions": getUserRolesResp.AllPermissions,
		"is_admin":        getUserRolesResp.IsAdmin,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helper function to parse int32 from string
func parseInt32(s string, defaultVal int32) int32 {
	if val, err := strconv.ParseInt(s, 10, 32); err == nil {
		return int32(val)
	}
	return defaultVal
}
