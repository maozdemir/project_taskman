package validation

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

var (
	// Email validation regex
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// UUID validation regex
	uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

// Validator provides validation functions
type Validator struct {
	errors []ValidationError
}

// New creates a new Validator
func New() *Validator {
	return &Validator{
		errors: make([]ValidationError, 0),
	}
}

// AddError adds a validation error
func (v *Validator) AddError(field, message string) {
	v.errors = append(v.errors, ValidationError{
		Field:   field,
		Message: message,
	})
}

// HasErrors returns true if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// Errors returns all validation errors
func (v *Validator) Errors() []ValidationError {
	return v.errors
}

// FirstError returns the first validation error
func (v *Validator) FirstError() *ValidationError {
	if len(v.errors) > 0 {
		return &v.errors[0]
	}
	return nil
}

// Required validates that a field is not empty
func (v *Validator) Required(field, value string) {
	if strings.TrimSpace(value) == "" {
		v.AddError(field, "is required")
	}
}

// MinLength validates minimum string length
func (v *Validator) MinLength(field, value string, min int) {
	if len(value) < min {
		v.AddError(field, fmt.Sprintf("must be at least %d characters", min))
	}
}

// MaxLength validates maximum string length
func (v *Validator) MaxLength(field, value string, max int) {
	if len(value) > max {
		v.AddError(field, fmt.Sprintf("must be at most %d characters", max))
	}
}

// Email validates email format
func (v *Validator) Email(field, value string) {
	if value == "" {
		return // Skip if empty (use Required for non-empty check)
	}

	// Try standard library first
	if _, err := mail.ParseAddress(value); err == nil {
		return
	}

	// Fallback to regex
	if !emailRegex.MatchString(value) {
		v.AddError(field, "invalid email format")
	}
}

// Password validates password strength
func (v *Validator) Password(field, value string) {
	if value == "" {
		return // Skip if empty
	}

	if len(value) < 8 {
		v.AddError(field, "must be at least 8 characters")
		return
	}

	// Check for at least one uppercase, one lowercase, and one digit (Go regex doesn't support lookaheads)
	hasUpper := false
	hasLower := false
	hasDigit := false

	for _, char := range value {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit {
		v.AddError(field, "must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number")
	}
}

// UUID validates UUID format
func (v *Validator) UUID(field, value string) {
	if value == "" {
		return // Skip if empty
	}

	if !uuidRegex.MatchString(strings.ToLower(value)) {
		v.AddError(field, "invalid UUID format")
	}
}

// In validates that a value is in a list of allowed values
func (v *Validator) In(field, value string, allowed []string) {
	if value == "" {
		return // Skip if empty
	}

	for _, a := range allowed {
		if value == a {
			return
		}
	}

	v.AddError(field, fmt.Sprintf("must be one of: %s", strings.Join(allowed, ", ")))
}

// Range validates that a number is within a range
func (v *Validator) Range(field string, value, min, max int) {
	if value < min || value > max {
		v.AddError(field, fmt.Sprintf("must be between %d and %d", min, max))
	}
}

// Helper functions for quick validation

// IsValidEmail checks if an email is valid
func IsValidEmail(email string) bool {
	if _, err := mail.ParseAddress(email); err == nil {
		return true
	}
	return emailRegex.MatchString(email)
}

// IsValidPassword checks if a password is valid
func IsValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		}
	}

	return hasUpper && hasLower && hasDigit
}

// IsValidUUID checks if a UUID is valid
func IsValidUUID(uuid string) bool {
	return uuidRegex.MatchString(strings.ToLower(uuid))
}

// IsEmpty checks if a string is empty or whitespace
func IsEmpty(value string) bool {
	return strings.TrimSpace(value) == ""
}