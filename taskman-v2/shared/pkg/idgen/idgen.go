package idgen

import "github.com/google/uuid"

// GenerateID generates a new UUID string
func GenerateID() string {
	return uuid.New().String()
}

// GenerateUserID generates a new user ID
func GenerateUserID() string {
	return GenerateID()
}

// GenerateCompanyID generates a new company ID
func GenerateCompanyID() string {
	return GenerateID()
}

// GenerateSessionID generates a new session ID
func GenerateSessionID() string {
	return GenerateID()
}

// GenerateRoleID generates a new role ID
func GenerateRoleID() string {
	return GenerateID()
}

// GenerateUserRoleID generates a new user-role assignment ID
func GenerateUserRoleID() string {
	return GenerateID()
}

// GenerateResetToken generates a new password reset token
func GenerateResetToken() string {
	return GenerateID()
}
