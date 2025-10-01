# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go module files first for better caching
COPY shared/go.mod shared/go.sum /build/shared/
COPY services/iam-admin-service/go.mod services/iam-admin-service/go.sum /build/services/iam-admin-service/

# Copy shared module
COPY shared /build/shared

# Copy iam-admin service files
COPY services/iam-admin-service /build/services/iam-admin-service

WORKDIR /build/services/iam-admin-service

# Download dependencies
RUN go mod download

# Build the gRPC server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o iam-server ./cmd/server

# Build the migration tool
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrate ./cmd/migrate

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/services/iam-admin-service/iam-server .
COPY --from=builder /build/services/iam-admin-service/migrate .

# Copy migration files
COPY --from=builder /build/services/iam-admin-service/migrations ./migrations

# Expose gRPC port
EXPOSE 50054

# Health check (optional, can be customized)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD pgrep -f iam-server || exit 1

# Run the gRPC server
CMD ["./iam-server"]
