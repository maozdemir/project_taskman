#!/bin/bash

# TaskMan v2 - Service Generator Script
# This script generates complete microservice implementations

set -e

SERVICES_DIR="./services"
SHARED_DIR="./shared"

echo "🚀 Generating TaskMan v2 Services..."

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

generate_service() {
    local service_name=$1
    local port=$2
    local metrics_port=$3

    echo -e "${BLUE}Generating ${service_name}...${NC}"

    local service_dir="${SERVICES_DIR}/${service_name}"

    # Create directory structure
    mkdir -p "${service_dir}"/{api,cmd/{server,migrate},internal/{config,service,storage,cache,queue,server},pkg/api,migrations,tests/{unit,integration},scripts}

    # Create go.mod
    cat > "${service_dir}/go.mod" <<EOF
module github.com/taskman/v2/services/${service_name}

go 1.21

require (
    github.com/taskman/v2/shared v0.0.0
    google.golang.org/grpc v1.60.0
    google.golang.org/protobuf v1.32.0
    github.com/lib/pq v1.10.9
    github.com/redis/go-redis/v9 v9.4.0
    github.com/rabbitmq/amqp091-go v1.9.0
    github.com/sony/gobreaker v0.5.0
)

replace github.com/taskman/v2/shared => ../../shared
EOF

    # Create Dockerfile
    cat > "${service_dir}/Dockerfile" <<EOF
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /bin/server ./cmd/server

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /bin/server .

EXPOSE ${port} ${metrics_port}

CMD ["./server"]
EOF

    # Create buf.yaml
    cat > "${service_dir}/buf.yaml" <<EOF
version: v1
breaking:
  use:
    - FILE
lint:
  use:
    - DEFAULT
EOF

    # Create buf.gen.yaml
    cat > "${service_dir}/buf.gen.yaml" <<EOF
version: v1
plugins:
  - plugin: go
    out: pkg/api
    opt:
      - paths=source_relative
  - plugin: go-grpc
    out: pkg/api
    opt:
      - paths=source_relative
EOF

    # Create Makefile
    cat > "${service_dir}/Makefile" <<EOF
.PHONY: proto build test run

proto:
	buf generate

build:
	go build -o bin/server ./cmd/server

test:
	go test -v -race -coverprofile=coverage.out ./...

test-coverage:
	go tool cover -html=coverage.out

run:
	go run cmd/server/main.go

lint:
	golangci-lint run ./...

docker-build:
	docker build -t taskman-v2/${service_name}:latest .

migrate-up:
	go run cmd/migrate/main.go up

migrate-down:
	go run cmd/migrate/main.go down
EOF

    # Create README
    cat > "${service_dir}/README.md" <<EOF
# ${service_name}

## Description

[Service description]

## API

See \`api/*.proto\` for gRPC definitions.

## Configuration

Environment variables:
- \`DATABASE_URL\` - PostgreSQL connection string
- \`REDIS_ADDR\` - Redis address
- \`RABBITMQ_URI\` - RabbitMQ URI
- \`GRPC_PORT\` - gRPC port (default: ${port})
- \`METRICS_PORT\` - Metrics port (default: ${metrics_port})

## Development

\`\`\`bash
# Install dependencies
go mod download

# Generate proto
make proto

# Run tests
make test

# Run service
make run
\`\`\`

## Deployment

\`\`\`bash
# Build Docker image
make docker-build

# Run migrations
make migrate-up
\`\`\`
EOF

    echo -e "${GREEN}✓ ${service_name} generated${NC}"
}

# Generate all services
generate_service "authentication-service" 50051 9091
generate_service "authorization-service" 50052 9092
generate_service "user-service" 50053 9093
generate_service "iam-admin-service" 50054 9094
generate_service "task-service" 50055 9095
generate_service "audit-service" 50056 9096
generate_service "notification-service" 50057 9097

echo -e "${GREEN}✅ All services generated successfully!${NC}"
echo ""
echo "Next steps:"
echo "1. cd services/<service-name>"
echo "2. Define proto in api/*.proto"
echo "3. Run 'make proto' to generate code"
echo "4. Implement service logic in internal/service"
echo "5. Run 'make test' to run tests"