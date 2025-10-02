# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go module files first for better caching
COPY shared/go.mod shared/go.sum /build/shared/
COPY services/authentication-service/go.mod services/authentication-service/go.sum /build/services/authentication-service/
COPY services/user-service/go.mod services/user-service/go.sum /build/services/user-service/
COPY services/iam-admin-service/go.mod services/iam-admin-service/go.sum /build/services/iam-admin-service/
COPY services/audit-service/go.mod services/audit-service/go.sum /build/services/audit-service/

# Copy shared module
COPY shared /build/shared

# Copy proto-generated code from other services (needed for gRPC clients)
COPY services/user-service/pkg /build/services/user-service/pkg
COPY services/iam-admin-service/pkg /build/services/iam-admin-service/pkg
COPY services/audit-service/pkg /build/services/audit-service/pkg

# Copy authentication service files
COPY services/authentication-service /build/services/authentication-service

WORKDIR /build/services/authentication-service

# Download dependencies
RUN go mod download

# Build the HTTP server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-http-server ./cmd/http-server

# Build the migration tool
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrate ./cmd/migrate

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata wget

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/services/authentication-service/auth-http-server .
COPY --from=builder /build/services/authentication-service/migrate .

# Copy migration files
COPY --from=builder /build/services/authentication-service/migrations ./migrations

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the HTTP server
CMD ["./auth-http-server"]
