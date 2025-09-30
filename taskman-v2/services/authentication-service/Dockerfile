# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy shared module first
COPY shared /build/shared

# Copy service files
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
