package errors

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AppError represents an application error with gRPC status
type AppError struct {
	Code    codes.Code
	Message string
	Details string
	Err     error
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (details: %s)", e.Message, e.Err.Error(), e.Details)
	}
	if e.Details != "" {
		return fmt.Sprintf("%s (details: %s)", e.Message, e.Details)
	}
	return e.Message
}

// ToGRPCError converts AppError to gRPC status error
func (e *AppError) ToGRPCError() error {
	return status.Error(e.Code, e.Error())
}

// Unwrap returns the wrapped error
func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates a new AppError
func New(code codes.Code, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code codes.Code, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// Common error constructors

// NotFound creates a not found error
func NotFound(resource string) *AppError {
	return New(codes.NotFound, fmt.Sprintf("%s not found", resource))
}

// AlreadyExists creates an already exists error
func AlreadyExists(resource string) *AppError {
	return New(codes.AlreadyExists, fmt.Sprintf("%s already exists", resource))
}

// InvalidArgument creates an invalid argument error
func InvalidArgument(field, reason string) *AppError {
	return New(codes.InvalidArgument, fmt.Sprintf("invalid %s: %s", field, reason))
}

// Unauthenticated creates an unauthenticated error
func Unauthenticated(message string) *AppError {
	return New(codes.Unauthenticated, message)
}

// PermissionDenied creates a permission denied error
func PermissionDenied(action string) *AppError {
	return New(codes.PermissionDenied, fmt.Sprintf("permission denied: %s", action))
}

// Internal creates an internal server error
func Internal(message string) *AppError {
	return New(codes.Internal, message)
}

// Unavailable creates an unavailable error
func Unavailable(service string) *AppError {
	return New(codes.Unavailable, fmt.Sprintf("%s is unavailable", service))
}

// DeadlineExceeded creates a deadline exceeded error
func DeadlineExceeded(operation string) *AppError {
	return New(codes.DeadlineExceeded, fmt.Sprintf("%s deadline exceeded", operation))
}

// ResourceExhausted creates a resource exhausted error
func ResourceExhausted(resource string) *AppError {
	return New(codes.ResourceExhausted, fmt.Sprintf("%s exhausted", resource))
}

// FailedPrecondition creates a failed precondition error
func FailedPrecondition(condition string) *AppError {
	return New(codes.FailedPrecondition, fmt.Sprintf("failed precondition: %s", condition))
}

// Aborted creates an aborted error
func Aborted(operation string) *AppError {
	return New(codes.Aborted, fmt.Sprintf("%s aborted", operation))
}

// OutOfRange creates an out of range error
func OutOfRange(field, value string) *AppError {
	return New(codes.OutOfRange, fmt.Sprintf("%s out of range: %s", field, value))
}

// Unimplemented creates an unimplemented error
func Unimplemented(feature string) *AppError {
	return New(codes.Unimplemented, fmt.Sprintf("%s not implemented", feature))
}

// DataLoss creates a data loss error
func DataLoss(details string) *AppError {
	return New(codes.DataLoss, fmt.Sprintf("data loss: %s", details))
}

// Predefined common errors
var (
	ErrUserNotFound         = NotFound("user")
	ErrRoleNotFound         = NotFound("role")
	ErrPolicyNotFound       = NotFound("policy")
	ErrTaskNotFound         = NotFound("task")
	ErrProjectNotFound      = NotFound("project")
	ErrCompanyNotFound      = NotFound("company")
	ErrSessionNotFound      = NotFound("session")
	ErrTokenNotFound        = NotFound("token")

	ErrUserAlreadyExists    = AlreadyExists("user")
	ErrRoleAlreadyExists    = AlreadyExists("role")
	ErrPolicyAlreadyExists  = AlreadyExists("policy")
	ErrTaskAlreadyExists    = AlreadyExists("task")
	ErrProjectAlreadyExists = AlreadyExists("project")

	ErrInvalidCredentials = Unauthenticated("invalid credentials")
	ErrInvalidToken       = Unauthenticated("invalid token")
	ErrExpiredToken       = Unauthenticated("token expired")
	ErrInvalidPassword    = InvalidArgument("password", "does not meet requirements")
	ErrInvalidEmail       = InvalidArgument("email", "invalid format")

	ErrDatabaseConnection = Unavailable("database")
	ErrCacheConnection    = Unavailable("cache")
	ErrQueueConnection    = Unavailable("message queue")

	ErrPermissionDenied = PermissionDenied("this action")

	ErrInternalServer = Internal("internal server error")
)