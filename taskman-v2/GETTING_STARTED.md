# Getting Started with TaskMan v2

## Overview

TaskMan v2 is a complete architectural rebuild with military-grade microservice principles. This guide will help you get started with development.

## Quick Start

### Prerequisites

- Go 1.21+ ([Download](https://golang.org/dl/))
- Docker 24+ ([Download](https://www.docker.com/products/docker-desktop))
- Docker Compose 2.0+ (included with Docker Desktop)
- Make (usually pre-installed on Linux/Mac, [Windows instructions](https://gnuwin32.sourceforge.net/packages/make.htm))
- Git

### 1. Clone the Repository

```bash
cd taskman-v2
```

### 2. Install Development Tools

```bash
make install
```

This installs:
- protoc (Protocol Buffer compiler)
- protoc-gen-go (Go protobuf plugin)
- protoc-gen-go-grpc (Go gRPC plugin)
- buf (Proto management tool)
- golangci-lint (Go linter)
- mockery (Mock generator)

### 3. Set Up Environment

```bash
make setup
```

This creates `.env` from `.env.example`. **Important:** Update `.env` with your configuration!

### 4. Start Infrastructure

```bash
make dev
```

This starts:
- 8 PostgreSQL databases (ports 5432-5438)
- Redis (port 6379)
- RabbitMQ (ports 5672, 15672)
- Vault (port 8200)
- Kong API Gateway (ports 8000-8002)
- Prometheus (port 9090)
- Grafana (port 3000)
- Jaeger (port 16686)
- MailHog (port 8025)

Wait 1-2 minutes for all services to be healthy.

### 5. Verify Infrastructure

```bash
# Check container status
docker-compose -f docker-compose.dev.yml ps

# All services should show "healthy" or "running"
```

### 6. Run a Service

```bash
# Terminal 1: Run authentication service
cd services/authentication-service
go run cmd/server/main.go

# Terminal 2: Run user service
cd services/user-service
go run cmd/server/main.go
```

## Project Structure

```
taskman-v2/
├── services/                       # Microservices
│   ├── authentication-service/    # JWT, login, sessions
│   ├── authorization-service/     # Policy evaluation (CEL)
│   ├── user-service/             # User CRUD
│   ├── iam-admin-service/        # Role/policy admin
│   ├── task-service/             # Task/project management
│   ├── audit-service/            # Event logging
│   ├── notification-service/     # Email, webhooks
│   └── api-gateway/              # Kong configuration
├── shared/                        # Shared libraries
│   └── pkg/
│       ├── config/               # Configuration
│       ├── logger/               # Structured logging
│       ├── errors/               # Error handling
│       ├── database/             # Database utilities
│       ├── cache/                # Redis utilities
│       ├── queue/                # RabbitMQ utilities
│       ├── middleware/           # gRPC middleware
│       ├── tracing/              # Distributed tracing
│       └── metrics/              # Prometheus metrics
├── infrastructure/                # Infrastructure configs
│   ├── postgres/
│   ├── redis/
│   ├── rabbitmq/
│   ├── vault/
│   ├── kong/
│   ├── prometheus/
│   ├── grafana/
│   └── jaeger/
├── k8s/                          # Kubernetes manifests
│   ├── base/                     # Namespaces, RBAC
│   ├── infrastructure/           # Databases, Redis, etc.
│   ├── services/                 # Service deployments
│   └── monitoring/               # Observability stack
├── docs/                         # Documentation
├── scripts/                      # Utility scripts
├── docker-compose.dev.yml        # Development environment
├── .env.example                  # Environment template
├── Makefile                      # Development commands
├── README.md                     # Project overview
├── ARCHITECTURE.md               # Architecture details
└── GETTING_STARTED.md           # This file
```

## Service Development

### Standard Service Structure

Each service follows this structure:

```
service-name/
├── api/                    # Proto definitions
│   └── service.proto
├── cmd/
│   ├── server/            # Main entry point
│   │   └── main.go
│   └── migrate/           # Database migrations
│       └── main.go
├── internal/              # Private application code
│   ├── config/
│   │   └── config.go     # Service config
│   ├── service/
│   │   └── service.go    # Business logic
│   ├── storage/
│   │   └── postgres.go   # Data access
│   ├── cache/
│   │   └── redis.go      # Caching layer
│   ├── queue/
│   │   └── rabbitmq.go   # Event publishing
│   └── server/
│       └── grpc.go       # gRPC server
├── pkg/                   # Public libraries
│   └── api/              # Generated proto code
│       ├── service.pb.go
│       └── service_grpc.pb.go
├── migrations/            # SQL migrations
│   ├── 001_initial.up.sql
│   └── 001_initial.down.sql
├── tests/                # Tests
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── Dockerfile            # Container image
├── buf.yaml              # Buf configuration
├── buf.gen.yaml          # Buf generation config
├── go.mod
├── go.sum
├── Makefile              # Service-specific commands
└── README.md             # Service documentation
```

### Creating a New Service

1. **Copy service template:**
```bash
cd services
cp -r authentication-service my-new-service
cd my-new-service
```

2. **Update go.mod:**
```bash
go mod init github.com/taskman/v2/services/my-new-service
go mod tidy
```

3. **Define proto:**
```protobuf
// api/my_service.proto
syntax = "proto3";

package myservice.v1;
option go_package = "github.com/taskman/v2/services/my-new-service/pkg/api";

service MyService {
  rpc DoSomething(DoSomethingRequest) returns (DoSomethingResponse);
}

message DoSomethingRequest {
  string param = 1;
}

message DoSomethingResponse {
  string result = 1;
}
```

4. **Generate code:**
```bash
buf generate
```

5. **Implement service:**
```go
// internal/service/service.go
package service

import (
    "context"
    pb "github.com/taskman/v2/services/my-new-service/pkg/api"
)

type Service struct {
    pb.UnimplementedMyServiceServer
    // dependencies
}

func (s *Service) DoSomething(ctx context.Context, req *pb.DoSomethingRequest) (*pb.DoSomethingResponse, error) {
    // Implementation
    return &pb.DoSomethingResponse{
        Result: "Done",
    }, nil
}
```

6. **Add to docker-compose.dev.yml:**
```yaml
  my-new-service:
    build:
      context: ./services/my-new-service
      dockerfile: Dockerfile
    container_name: taskman-v2-my-new-service
    ports:
      - "50058:50051"  # gRPC
      - "9098:9090"    # Metrics
    environment:
      DATABASE_URL: "postgresql://myservice_user:password@postgres-myservice:5432/myservice_db"
      REDIS_ADDR: "redis:6379"
      RABBITMQ_URI: "amqp://taskman:password@rabbitmq:5672/"
    depends_on:
      postgres-myservice:
        condition: service_healthy
    networks:
      - taskman-network
    restart: unless-stopped
```

## Working with the Stack

### Accessing Services

**Web UIs:**
- RabbitMQ Management: http://localhost:15672 (user: `taskman`, pass: `rabbitmq_password_dev`)
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (user: `admin`, pass: `admin`)
- Jaeger: http://localhost:16686
- Kong Manager: http://localhost:8002
- Vault: http://localhost:8200 (token: `dev-root-token`)
- MailHog: http://localhost:8025

**gRPC Services:**
```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services
grpcurl -plaintext localhost:50051 list

# Call a method
grpcurl -plaintext -d '{"email": "user@example.com", "password": "password"}' \
  localhost:50051 authentication.v1.AuthenticationService/Login
```

### Database Access

```bash
# Connect to authentication database
docker exec -it taskman-v2-postgres-auth psql -U auth_user -d auth_db

# List tables
\dt

# Query
SELECT * FROM sessions;
```

### Viewing Logs

```bash
# All services
make logs

# Specific service
make logs-service SERVICE=postgres-auth

# Follow service logs
docker-compose -f docker-compose.dev.yml logs -f authentication-service
```

### Running Tests

```bash
# Run all tests
make test

# Test with coverage
make test-coverage

# Run linters
make lint

# Test a specific service
cd services/authentication-service
go test -v ./...
```

### Building Services

```bash
# Build all services
make build

# Binaries will be in ./bin/

# Build Docker images
make docker-build
```

## Development Workflow

### 1. Make Changes

Edit code in your favorite editor (VS Code, GoLand, etc.)

### 2. Run Tests

```bash
cd services/authentication-service
go test -v ./internal/service/
```

### 3. Run Service Locally

```bash
go run cmd/server/main.go
```

### 4. Test with grpcurl

```bash
grpcurl -plaintext -d '{"email": "test@example.com"}' \
  localhost:50051 authentication.v1.AuthenticationService/GetUser
```

### 5. Check Logs

```bash
# Service logs (JSON format)
docker-compose -f docker-compose.dev.yml logs authentication-service

# Database queries
docker-compose -f docker-compose.dev.yml logs postgres-auth
```

### 6. Monitor Metrics

Open Grafana (http://localhost:3000), import dashboard from `infrastructure/grafana/dashboards/`

### 7. Commit Changes

```bash
git add .
git commit -m "feat(auth): add password reset endpoint"
git push
```

## Common Tasks

### Reset Everything

```bash
make clean  # Stops containers, removes volumes
make dev    # Start fresh
```

### Run Database Migrations

```bash
make migrate-up
```

### Rollback Migrations

```bash
make migrate-down
```

### Generate Proto Code

```bash
make proto
```

### View RabbitMQ Queues

1. Open http://localhost:15672
2. Click "Queues" tab
3. See message rates, depths

### Configure Kong Routes

```bash
# Add route to authentication service
curl -i -X POST http://localhost:8001/services \
  --data name=authentication-service \
  --data url='http://authentication-service:50051'

curl -i -X POST http://localhost:8001/services/authentication-service/routes \
  --data 'paths[]=/auth' \
  --data name=auth-route
```

### Initialize Vault

```bash
./scripts/vault-init.sh
```

## Troubleshooting

### Service Won't Start

1. Check logs:
```bash
docker-compose -f docker-compose.dev.yml logs <service-name>
```

2. Check database connection:
```bash
docker exec -it taskman-v2-postgres-auth pg_isready
```

3. Check environment variables:
```bash
docker-compose -f docker-compose.dev.yml config
```

### Database Connection Error

```bash
# Check if database is running
docker ps | grep postgres

# Check logs
docker logs taskman-v2-postgres-auth

# Verify credentials in .env file
```

### RabbitMQ Connection Error

```bash
# Check if RabbitMQ is running
docker ps | grep rabbitmq

# Check management UI
open http://localhost:15672

# Verify credentials in .env file
```

### Port Already in Use

```bash
# Find process using port
lsof -i :5432  # Mac/Linux
netstat -ano | findstr :5432  # Windows

# Kill process or change port in docker-compose.dev.yml
```

### Out of Disk Space

```bash
# Clean up Docker
docker system prune -a --volumes

# Clean up build artifacts
make clean
```

## Next Steps

1. **Read Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md)
2. **Explore Services:** Check each service's README
3. **Run Examples:** See `examples/` directory
4. **Write Tests:** Add tests for your changes
5. **Deploy to K8s:** Follow [k8s/README.md](k8s/README.md)

## Getting Help

- **Documentation:** See `docs/` directory
- **Issues:** GitHub Issues
- **Slack:** #taskman-dev channel
- **Email:** dev-team@taskman.local

## Contributing

1. Create feature branch: `git checkout -b feature/my-feature`
2. Make changes with tests
3. Run linters: `make lint`
4. Run tests: `make test`
5. Commit: `git commit -m "feat: description"`
6. Push: `git push origin feature/my-feature`
7. Open Pull Request

## License

Proprietary - TaskMan v2