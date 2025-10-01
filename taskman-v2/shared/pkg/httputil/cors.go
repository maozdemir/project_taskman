package httputil

import (
	"net/http"
	"os"
	"strings"
)

// CORSMiddleware adds CORS headers to HTTP responses with strict origin whitelisting
func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// Define allowed origins - production should use environment variable
	allowedOrigins := getAllowedOrigins()

	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Only set CORS headers if origin is in whitelist
		if isOriginAllowed(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// getAllowedOrigins returns the list of allowed origins
func getAllowedOrigins() []string {
	// Check environment variable first
	envOrigins := os.Getenv("ALLOWED_ORIGINS")
	if envOrigins != "" {
		return strings.Split(envOrigins, ",")
	}

	// Default allowed origins for development
	return []string{
		"http://localhost:3000",
		"http://localhost:4000",
		"http://localhost:8080",
	}
}

// isOriginAllowed checks if the origin is in the whitelist
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range allowedOrigins {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
}

// CORSMiddlewareWithConfig creates a CORS middleware with custom configuration
func CORSMiddlewareWithConfig(config CORSConfig) func(http.HandlerFunc) http.HandlerFunc {
	allowedOrigins := "*"
	if len(config.AllowedOrigins) > 0 {
		allowedOrigins = config.AllowedOrigins[0] // simplified for now
	}

	allowedMethods := "GET, POST, PUT, DELETE, OPTIONS"
	if len(config.AllowedMethods) > 0 {
		allowedMethods = join(config.AllowedMethods, ", ")
	}

	allowedHeaders := "Content-Type, Authorization"
	if len(config.AllowedHeaders) > 0 {
		allowedHeaders = join(config.AllowedHeaders, ", ")
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigins)
			w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next(w, r)
		}
	}
}

func join(slice []string, sep string) string {
	if len(slice) == 0 {
		return ""
	}
	result := slice[0]
	for i := 1; i < len(slice); i++ {
		result += sep + slice[i]
	}
	return result
}
