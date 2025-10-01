package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims represents JWT claims
type Claims struct {
	UserID      string   `json:"sub"`
	Email       string   `json:"email"`
	Username    string   `json:"username"`
	CompanyID   string   `json:"company_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	SessionID   string   `json:"session_id"` // Session ID for token revocation
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
	JTI         string   `json:"jti"` // JWT ID (same as SessionID for compatibility)
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// Manager handles JWT token operations
type Manager struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

// NewManager creates a new JWT manager
func NewManager(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

// GenerateTokenPair generates both access and refresh tokens
func (m *Manager) GenerateTokenPair(userID, email, username, companyID string, roles []string, permissions []string, jti string) (*TokenPair, error) {
	now := time.Now()
	accessExpiresAt := now.Add(m.accessTTL)
	refreshExpiresAt := now.Add(m.refreshTTL)

	// Generate access token
	accessClaims := &Claims{
		UserID:      userID,
		Email:       email,
		Username:    username,
		CompanyID:   companyID,
		Roles:       roles,
		Permissions: permissions,
		SessionID:   jti,
		IssuedAt:    now.Unix(),
		ExpiresAt:   accessExpiresAt.Unix(),
		JTI:         jti,
	}

	accessToken, err := m.generateToken(accessClaims, m.accessSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := &Claims{
		UserID:      userID,
		Email:       email,
		Username:    username,
		CompanyID:   companyID,
		Roles:       roles,
		Permissions: permissions,
		SessionID:   jti,
		IssuedAt:    now.Unix(),
		ExpiresAt:   refreshExpiresAt.Unix(),
		JTI:         jti + "-refresh",
	}

	refreshToken, err := m.generateToken(refreshClaims, m.refreshSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiresAt,
	}, nil
}

// generateToken generates a JWT token
func (m *Manager) generateToken(claims *Claims, secret []byte) (string, error) {
	// Create header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Create payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encode header and payload
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	message := encodedHeader + "." + encodedPayload
	signature := m.sign(message, secret)

	// Combine parts
	token := message + "." + signature

	return token, nil
}

// VerifyAccessToken verifies an access token
func (m *Manager) VerifyAccessToken(token string) (*Claims, error) {
	return m.verifyToken(token, m.accessSecret)
}

// VerifyRefreshToken verifies a refresh token
func (m *Manager) VerifyRefreshToken(token string) (*Claims, error) {
	return m.verifyToken(token, m.refreshSecret)
}

// verifyToken verifies a JWT token
func (m *Manager) verifyToken(token string, secret []byte) (*Claims, error) {
	// Split token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	encodedHeader := parts[0]
	encodedPayload := parts[1]
	providedSignature := parts[2]

	// Verify signature using constant-time comparison to prevent timing attacks
	message := encodedHeader + "." + encodedPayload
	expectedSignature := m.sign(message, secret)

	// SECURITY: Use hmac.Equal for constant-time comparison
	if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Parse claims
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Check expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// sign creates a signature using HMAC SHA256
func (m *Manager) sign(message string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	signature := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature)
}

// ParseWithoutVerify parses a token without verifying it (useful for debugging)
func ParseWithoutVerify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &claims, nil
}

// ExtractToken extracts a token from "Bearer <token>" format
func ExtractToken(authHeader string) (string, error) {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}
	return parts[1], nil
}