package handlers

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/taskman/v2/services/authentication-service/internal/clients"
	"github.com/taskman/v2/services/authentication-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/httputil"
	"github.com/taskman/v2/shared/pkg/idgen"
	"github.com/taskman/v2/shared/pkg/jwt"
	"github.com/taskman/v2/shared/pkg/queue"
)

// Handler holds all dependencies for HTTP handlers
type Handler struct {
	DB          *database.DB
	Cache       *cache.Cache
	Queue       *queue.Queue
	JWTManager  *jwt.Manager
	Storage     *storage.Storage
	UserClient  *clients.UserClient
	IAMClient   *clients.IAMClient
	AuditClient *clients.AuditClient
	Logger      *slog.Logger
}

// Helper methods

// extractIPAddress extracts the IP address from RemoteAddr (strips port if present)
func extractIPAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If there's no port, return as-is
		return remoteAddr
	}
	return host
}

func (h *Handler) recordFailedLogin(ctx context.Context, email, ipAddress string) {
	attempt := &storage.LoginAttempt{
		ID:        idgen.GenerateID(),
		Email:     email,
		IPAddress: ipAddress,
		Success:   false,
		CreatedAt: time.Now(),
	}
	if err := h.Storage.RecordLoginAttempt(ctx, attempt); err != nil {
		h.Logger.Warn("failed to record login attempt", "error", err)
	}
}

func (h *Handler) recordSuccessfulLogin(ctx context.Context, email, ipAddress string) {
	attempt := &storage.LoginAttempt{
		ID:        idgen.GenerateID(),
		Email:     email,
		IPAddress: ipAddress,
		Success:   true,
		CreatedAt: time.Now(),
	}
	if err := h.Storage.RecordLoginAttempt(ctx, attempt); err != nil {
		h.Logger.Warn("failed to record login attempt", "error", err)
	}
}

func respondWithError(w http.ResponseWriter, status int, code, message string) {
	httputil.RespondWithError(w, status, code, message)
}
