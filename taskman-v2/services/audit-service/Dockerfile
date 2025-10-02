# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go module files first for better caching
COPY shared/go.mod shared/go.sum /build/shared/
COPY services/audit-service/go.mod services/audit-service/go.sum /build/services/audit-service/

# Copy shared module
COPY shared /build/shared

# Copy audit service files
COPY services/audit-service /build/services/audit-service

WORKDIR /build/services/audit-service

# Download dependencies
RUN go mod download

# Build the gRPC server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o audit-server ./cmd/server

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/services/audit-service/audit-server .

# Copy migration files
COPY --from=builder /build/services/audit-service/migrations ./migrations

# Expose gRPC and metrics ports
EXPOSE 50056 9096

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD pgrep -f audit-server || exit 1

# Run the gRPC server
CMD ["./audit-server"]
