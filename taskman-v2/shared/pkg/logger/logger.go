package logger

import (
	"context"
	"log/slog"
	"os"
)

type contextKey string

const loggerKey contextKey = "logger"

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
}

// New creates a new logger instance
func New(serviceName, level string, isDevelopment bool) *Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
		AddSource: isDevelopment,
	}

	if isDevelopment {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler).With(
		slog.String("service", serviceName),
	)

	return &Logger{Logger: logger}
}

// WithContext adds logger to context
func (l *Logger) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext retrieves logger from context
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	// Return default logger if not found in context
	return New("default", "info", false)
}

// WithFields creates a new logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	args := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return &Logger{Logger: l.Logger.With(args...)}
}

// WithError adds error to logger
func (l *Logger) WithError(err error) *Logger {
	return &Logger{Logger: l.Logger.With(slog.String("error", err.Error()))}
}

// WithRequestID adds request ID to logger
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{Logger: l.Logger.With(slog.String("request_id", requestID))}
}

// WithUserID adds user ID to logger
func (l *Logger) WithUserID(userID string) *Logger {
	return &Logger{Logger: l.Logger.With(slog.String("user_id", userID))}
}

// WithCompanyID adds company ID to logger
func (l *Logger) WithCompanyID(companyID string) *Logger {
	return &Logger{Logger: l.Logger.With(slog.String("company_id", companyID))}
}

// Helper function to parse log level
func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// LogHTTPRequest logs an HTTP request
func (l *Logger) LogHTTPRequest(method, path string, statusCode int, duration int64, requestID string) {
	l.Info("HTTP request",
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status_code", statusCode),
		slog.Int64("duration_ms", duration),
		slog.String("request_id", requestID),
	)
}

// LogGRPCRequest logs a gRPC request
func (l *Logger) LogGRPCRequest(method string, duration int64, err error, requestID string) {
	if err != nil {
		l.Error("gRPC request failed",
			slog.String("method", method),
			slog.Int64("duration_ms", duration),
			slog.String("error", err.Error()),
			slog.String("request_id", requestID),
		)
	} else {
		l.Info("gRPC request",
			slog.String("method", method),
			slog.Int64("duration_ms", duration),
			slog.String("request_id", requestID),
		)
	}
}

// LogDatabaseQuery logs a database query
func (l *Logger) LogDatabaseQuery(query string, duration int64, err error) {
	if err != nil {
		l.Error("Database query failed",
			slog.String("query", query),
			slog.Int64("duration_ms", duration),
			slog.String("error", err.Error()),
		)
	} else {
		l.Debug("Database query",
			slog.String("query", query),
			slog.Int64("duration_ms", duration),
		)
	}
}

// LogCacheOperation logs a cache operation
func (l *Logger) LogCacheOperation(operation, key string, hit bool, duration int64) {
	l.Debug("Cache operation",
		slog.String("operation", operation),
		slog.String("key", key),
		slog.Bool("hit", hit),
		slog.Int64("duration_ms", duration),
	)
}

// LogQueueMessage logs a queue message
func (l *Logger) LogQueueMessage(exchange, routingKey string, success bool, err error) {
	if err != nil {
		l.Error("Queue message failed",
			slog.String("exchange", exchange),
			slog.String("routing_key", routingKey),
			slog.String("error", err.Error()),
		)
	} else {
		l.Info("Queue message",
			slog.String("exchange", exchange),
			slog.String("routing_key", routingKey),
			slog.Bool("success", success),
		)
	}
}