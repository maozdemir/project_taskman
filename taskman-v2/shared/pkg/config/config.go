package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// BaseConfig contains configuration common to all services
type BaseConfig struct {
	// Service
	ServiceName string
	Environment string
	Port        int
	GRPCPort    int
	MetricsPort int

	// Database
	DatabaseURL string
	DBMaxConns  int
	DBMaxIdle   int
	DBTimeout   time.Duration

	// Redis
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// RabbitMQ
	RabbitMQURI string

	// JWT (for services that need it)
	JWTAccessSecret  string
	JWTRefreshSecret string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration

	// Observability
	EnableTracing bool
	EnableMetrics bool
	JaegerEndpoint string
	LogLevel      string

	// Vault
	VaultAddr  string
	VaultToken string
}

// LoadBaseConfig loads common configuration from environment variables
func LoadBaseConfig(serviceName string, defaultPort, defaultGRPCPort, defaultMetricsPort int) *BaseConfig {
	return &BaseConfig{
		ServiceName: serviceName,
		Environment: getEnv("ENVIRONMENT", "development"),
		Port:        getEnvAsInt("PORT", defaultPort),
		GRPCPort:    getEnvAsInt("GRPC_PORT", defaultGRPCPort),
		MetricsPort: getEnvAsInt("METRICS_PORT", defaultMetricsPort),

		// Database
		DatabaseURL: getEnv("DATABASE_URL", ""),
		DBMaxConns:  getEnvAsInt("DB_MAX_CONNS", 25),
		DBMaxIdle:   getEnvAsInt("DB_MAX_IDLE", 5),
		DBTimeout:   getEnvAsDuration("DB_TIMEOUT", 30*time.Second),

		// Redis
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvAsInt("REDIS_DB", 0),

		// RabbitMQ
		RabbitMQURI: getEnv("RABBITMQ_URI", "amqp://taskman:rabbitmq_password_dev@localhost:5672/"),

		// JWT
		JWTAccessSecret:  getEnv("JWT_ACCESS_SECRET", ""),
		JWTRefreshSecret: getEnv("JWT_REFRESH_SECRET", ""),
		AccessTokenTTL:   getEnvAsDuration("ACCESS_TOKEN_TTL", 1*time.Hour),
		RefreshTokenTTL:  getEnvAsDuration("REFRESH_TOKEN_TTL", 168*time.Hour), // 7 days

		// Observability
		EnableTracing:  getEnvAsBool("ENABLE_TRACING", true),
		EnableMetrics:  getEnvAsBool("ENABLE_METRICS", true),
		JaegerEndpoint: getEnv("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
		LogLevel:       getEnv("LOG_LEVEL", "info"),

		// Vault
		VaultAddr:  getEnv("VAULT_ADDR", "http://localhost:8200"),
		VaultToken: getEnv("VAULT_TOKEN", "dev-root-token"),
	}
}

// Validate validates the configuration
func (c *BaseConfig) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	if c.ServiceName == "" {
		return fmt.Errorf("service name is required")
	}

	return nil
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if value, err := time.ParseDuration(valueStr); err == nil {
		return value
	}
	return defaultValue
}

// IsDevelopment returns true if running in development environment
func (c *BaseConfig) IsDevelopment() bool {
	return c.Environment == "development" || c.Environment == "dev"
}

// IsProduction returns true if running in production environment
func (c *BaseConfig) IsProduction() bool {
	return c.Environment == "production" || c.Environment == "prod"
}

// IsStaging returns true if running in staging environment
func (c *BaseConfig) IsStaging() bool {
	return c.Environment == "staging" || c.Environment == "stage"
}