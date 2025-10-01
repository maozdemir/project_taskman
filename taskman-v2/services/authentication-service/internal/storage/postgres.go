package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/idgen"
)

// Session represents a user session
type Session struct {
	ID           string
	UserID       string
	RefreshToken string
	IPAddress    string
	UserAgent    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	IsActive     bool
}

// PasswordReset represents a password reset request
type PasswordReset struct {
	ID        string
	UserID    string
	Token     string
	ExpiresAt time.Time
	Used      bool
	UsedAt    *time.Time
	IPAddress string
	CreatedAt time.Time
}

// LoginAttempt represents a login attempt
type LoginAttempt struct {
	ID           string
	Email        string
	IPAddress    string
	Success      bool
	ErrorMessage string
	CreatedAt    time.Time
}

// Storage provides database operations for authentication service
type Storage struct {
	db *database.DB
}

// New creates a new Storage instance
func New(db *database.DB) *Storage {
	return &Storage{db: db}
}

// CreateSession creates a new session
func (s *Storage) CreateSession(ctx context.Context, session *Session) error {
	query := `
		INSERT INTO sessions (id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at, updated_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := s.db.ExecContext(ctx, query,
		session.ID,
		session.UserID,
		session.RefreshToken,
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
		session.CreatedAt,
		session.UpdatedAt,
		session.IsActive,
	)

	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to create session").Code, "failed to insert session")
	}

	return nil
}

// GetSession retrieves a session by ID
func (s *Storage) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	query := `
		SELECT id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at, updated_at, is_active
		FROM sessions
		WHERE id = $1
	`

	var session Session
	err := s.db.QueryRowContext(ctx, query, sessionID).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshToken,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
		&session.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound("session")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.Internal("failed to get session").Code, "failed to query session")
	}

	return &session, nil
}

// GetSessionByRefreshToken retrieves a session by refresh token
func (s *Storage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*Session, error) {
	query := `
		SELECT id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at, updated_at, is_active
		FROM sessions
		WHERE refresh_token = $1 AND is_active = TRUE
	`

	var session Session
	err := s.db.QueryRowContext(ctx, query, refreshToken).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshToken,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
		&session.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound("session")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.Internal("failed to get session").Code, "failed to query session")
	}

	return &session, nil
}

// ListSessionsByUserID lists all sessions for a user
func (s *Storage) ListSessionsByUserID(ctx context.Context, userID string) ([]*Session, error) {
	query := `
		SELECT id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at, updated_at, is_active
		FROM sessions
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.Internal("failed to list sessions").Code, "failed to query sessions")
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var session Session
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshToken,
			&session.IPAddress,
			&session.UserAgent,
			&session.ExpiresAt,
			&session.CreatedAt,
			&session.UpdatedAt,
			&session.IsActive,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.Internal("failed to scan session").Code, "failed to scan session row")
		}
		sessions = append(sessions, &session)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.Internal("failed to iterate sessions").Code, "failed to iterate rows")
	}

	return sessions, nil
}

// RevokeSession revokes a session
func (s *Storage) RevokeSession(ctx context.Context, sessionID string) error {
	query := `
		UPDATE sessions
		SET is_active = FALSE, updated_at = NOW()
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query, sessionID)
	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to revoke session").Code, "failed to update session")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to check rows affected").Code, "failed to check result")
	}

	if rowsAffected == 0 {
		return errors.NotFound("session")
	}

	return nil
}

// DeleteExpiredSessions deletes expired sessions
func (s *Storage) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM sessions
		WHERE expires_at < NOW()
	`

	result, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return 0, errors.Wrap(err, errors.Internal("failed to delete expired sessions").Code, "failed to delete sessions")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, errors.Internal("failed to check rows affected").Code, "failed to check result")
	}

	return rowsAffected, nil
}

// CreatePasswordReset creates a new password reset token
func (s *Storage) CreatePasswordReset(ctx context.Context, reset *PasswordReset) error {
	query := `
		INSERT INTO password_resets (id, user_id, token, expires_at, used, ip_address, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.db.ExecContext(ctx, query,
		reset.ID,
		reset.UserID,
		reset.Token,
		reset.ExpiresAt,
		reset.Used,
		reset.IPAddress,
		reset.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to create password reset").Code, "failed to insert password reset")
	}

	return nil
}

// GetPasswordReset retrieves a password reset by token
func (s *Storage) GetPasswordReset(ctx context.Context, token string) (*PasswordReset, error) {
	query := `
		SELECT id, user_id, token, expires_at, used, used_at, ip_address, created_at
		FROM password_resets
		WHERE token = $1 AND used = FALSE AND expires_at > NOW()
	`

	var reset PasswordReset
	var usedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, query, token).Scan(
		&reset.ID,
		&reset.UserID,
		&reset.Token,
		&reset.ExpiresAt,
		&reset.Used,
		&usedAt,
		&reset.IPAddress,
		&reset.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound("password reset token")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.Internal("failed to get password reset").Code, "failed to query password reset")
	}

	if usedAt.Valid {
		reset.UsedAt = &usedAt.Time
	}

	return &reset, nil
}

// MarkPasswordResetAsUsed marks a password reset token as used
func (s *Storage) MarkPasswordResetAsUsed(ctx context.Context, resetID string) error {
	query := `
		UPDATE password_resets
		SET used = TRUE, used_at = NOW()
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query, resetID)
	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to mark password reset as used").Code, "failed to update password reset")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to check rows affected").Code, "failed to check result")
	}

	if rowsAffected == 0 {
		return errors.NotFound("password reset")
	}

	return nil
}

// RecordLoginAttempt records a login attempt
func (s *Storage) RecordLoginAttempt(ctx context.Context, attempt *LoginAttempt) error {
	query := `
		INSERT INTO login_attempts (id, email, ip_address, success, error_message, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := s.db.ExecContext(ctx, query,
		attempt.ID,
		attempt.Email,
		attempt.IPAddress,
		attempt.Success,
		attempt.ErrorMessage,
		attempt.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to record login attempt").Code, "failed to insert login attempt")
	}

	return nil
}

// GetRecentLoginAttempts gets recent login attempts for rate limiting
func (s *Storage) GetRecentLoginAttempts(ctx context.Context, email string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM login_attempts
		WHERE email = $1 AND created_at > $2
	`

	var count int
	err := s.db.QueryRowContext(ctx, query, email, since).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.Internal("failed to get login attempts").Code, "failed to query login attempts")
	}

	return count, nil
}

// GenerateSessionID generates a new session ID
func GenerateSessionID() string {
	return idgen.GenerateSessionID()
}

// GenerateResetToken generates a new password reset token
func GenerateResetToken() string {
	return idgen.GenerateResetToken()
}