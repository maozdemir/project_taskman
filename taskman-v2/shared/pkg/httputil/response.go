package httputil

import (
	"encoding/json"
	"net/http"
)

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
	Error   *ErrorDetail `json:"error,omitempty"`
}

// ErrorDetail represents error details in a response
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// RespondWithJSON sends a JSON response
func RespondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// RespondWithSuccess sends a successful JSON response
func RespondWithSuccess(w http.ResponseWriter, status int, data interface{}) {
	RespondWithJSON(w, status, Response{
		Success: true,
		Data:    data,
	})
}

// RespondWithError sends an error JSON response
func RespondWithError(w http.ResponseWriter, status int, code, message string) {
	RespondWithJSON(w, status, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// RespondWithMessage sends a simple message response
func RespondWithMessage(w http.ResponseWriter, status int, message string) {
	RespondWithJSON(w, status, Response{
		Success: true,
		Message: message,
	})
}
