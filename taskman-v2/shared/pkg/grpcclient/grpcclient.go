package grpcclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config represents gRPC client configuration
type Config struct {
	Addr            string
	Timeout         time.Duration
	MaxRetries      int
	EnableKeepAlive bool
}

// DefaultConfig returns default gRPC client configuration
func DefaultConfig(addr string) *Config {
	return &Config{
		Addr:            addr,
		Timeout:         5 * time.Second,
		MaxRetries:      3,
		EnableKeepAlive: true,
	}
}

// Connect creates a new gRPC client connection with the given configuration
func Connect(config *Config) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	conn, err := grpc.DialContext(ctx, config.Addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC service at %s: %w", config.Addr, err)
	}

	return conn, nil
}

// MustConnect creates a new gRPC client connection and panics on error
func MustConnect(addr string) *grpc.ClientConn {
	conn, err := Connect(DefaultConfig(addr))
	if err != nil {
		panic(err)
	}
	return conn
}
