package handlers

import "github.com/taskman/v2/shared/pkg/httputil"

// Request types
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

// Response types
type AuthResponse struct {
	Success bool                  `json:"success"`
	Data    interface{}           `json:"data,omitempty"`
	Message string                `json:"message,omitempty"`
	Error   *httputil.ErrorDetail `json:"error,omitempty"`
}
