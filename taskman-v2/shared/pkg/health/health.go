package health

import (
	"context"
	"time"
)

// Status represents the health status of a component
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

// CheckResult represents the result of a health check
type CheckResult struct {
	Component string        `json:"component"`
	Status    Status        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Duration  time.Duration `json:"duration_ms"`
	Error     string        `json:"error,omitempty"`
}

// Checker defines a health check interface
type Checker interface {
	Check(ctx context.Context) error
	Name() string
}

// CheckFunc is a function that implements Checker
type CheckFunc struct {
	name string
	fn   func(ctx context.Context) error
}

// NewCheckFunc creates a new CheckFunc
func NewCheckFunc(name string, fn func(ctx context.Context) error) *CheckFunc {
	return &CheckFunc{
		name: name,
		fn:   fn,
	}
}

// Check implements Checker
func (c *CheckFunc) Check(ctx context.Context) error {
	return c.fn(ctx)
}

// Name implements Checker
func (c *CheckFunc) Name() string {
	return c.name
}

// HealthChecker manages multiple health checks
type HealthChecker struct {
	checkers []Checker
}

// New creates a new HealthChecker
func New() *HealthChecker {
	return &HealthChecker{
		checkers: make([]Checker, 0),
	}
}

// Register registers a health checker
func (h *HealthChecker) Register(checker Checker) {
	h.checkers = append(h.checkers, checker)
}

// RegisterFunc registers a health check function
func (h *HealthChecker) RegisterFunc(name string, fn func(ctx context.Context) error) {
	h.Register(NewCheckFunc(name, fn))
}

// Check runs all health checks
func (h *HealthChecker) Check(ctx context.Context) []CheckResult {
	results := make([]CheckResult, 0, len(h.checkers))

	for _, checker := range h.checkers {
		start := time.Now()
		err := checker.Check(ctx)
		duration := time.Since(start)

		result := CheckResult{
			Component: checker.Name(),
			Duration:  duration,
		}

		if err != nil {
			result.Status = StatusUnhealthy
			result.Error = err.Error()
			result.Message = "health check failed"
		} else {
			result.Status = StatusHealthy
			result.Message = "healthy"
		}

		results = append(results, result)
	}

	return results
}

// IsHealthy returns true if all checks are healthy
func (h *HealthChecker) IsHealthy(ctx context.Context) bool {
	results := h.Check(ctx)
	for _, result := range results {
		if result.Status != StatusHealthy {
			return false
		}
	}
	return true
}