# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go module files first for better caching
COPY shared/go.mod shared/go.sum /build/shared/
COPY services/user-service/go.mod services/user-service/go.sum /build/services/user-service/
COPY services/iam-admin-service/go.mod services/iam-admin-service/go.sum /build/services/iam-admin-service/

# Copy shared module
COPY shared /build/shared

# Copy proto-generated code from iam-admin-service (needed for gRPC client)
COPY services/iam-admin-service/pkg /build/services/iam-admin-service/pkg

# Copy user service files
COPY services/user-service /build/services/user-service

WORKDIR /build/services/user-service

# Download dependencies
RUN go mod download

# Build the gRPC server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o user-server ./cmd/server

# Build the migration tool
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrate ./cmd/migrate

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/services/user-service/user-server .
COPY --from=builder /build/services/user-service/migrate .

# Copy migration files
COPY --from=builder /build/services/user-service/migrations ./migrations

# Expose gRPC port
EXPOSE 50053

# Health check (optional, can be customized)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD pgrep -f user-server || exit 1

# Run the gRPC server
CMD ["./user-server"]
