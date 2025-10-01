# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TaskMan is a microservices-based task management platform with two implementations:
- **taskman-v2**: Military-grade microservices architecture (Go backend)
- **taskman-frontend**: Next.js 15 frontend with TypeScript

## Common Commands

### Backend (taskman-v2)

**Development Environment:**
```bash
# Start all infrastructure (PostgreSQL, Redis, RabbitMQ, monitoring)
make dev
# or
docker-compose -f docker-compose.dev.yml up -d

# Stop environment
make down
```

**Running Individual Services:**
```bash
# Authentication service (gRPC + HTTP)
cd taskman-v2/services/authentication-service
DATABASE_URL="postgresql://auth_user:auth_password_dev@localhost:5432/auth_db?sslmode=disable" \
REDIS_ADDR="localhost:6379" \
REDIS_PASSWORD="redis_password_dev" \
RABBITMQ_URI="amqp://taskman:rabbitmq_password_dev@localhost:5672/" \
JWT_ACCESS_SECRET="dev-secret-key-min-32-characters-long-for-testing" \
JWT_REFRESH_SECRET="dev-refresh-secret-key-min-32-characters-long-for-testing" \
HTTP_PORT=8080 \
go run cmd/http-server/main.go

# gRPC server
GRPC_PORT=50051 go run cmd/server/main.go
```

**Database Migrations:**
```bash
# Run migrations for authentication service
cd taskman-v2/services/authentication-service
DATABASE_URL="postgresql://auth_user:auth_password_dev@localhost:5432/auth_db?sslmode=disable" \
go run cmd/migrate/main.go

# Create admin user
cd taskman-v2/scripts
DATABASE_URL="postgresql://auth_user:auth_password_dev@localhost:5432/auth_db?sslmode=disable" \
go run create-admin.go
```

**Testing & Linting:**
```bash
# Run tests
make test

# Run linters
make lint

# Generate protobuf code
make proto

# Build all services
make build
```

### Frontend (taskman-frontend)

```bash
cd taskman-frontend

# Development server (port 4000)
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Lint
npm run lint
```

## Architecture

### Backend Microservices (taskman-v2)

The v2 backend follows strict microservices principles with **database-per-service** pattern:

**Services:**
1. **Authentication Service** (Port 50051 gRPC, 8080 HTTP)
   - User login/logout, JWT token generation/validation
   - Session management (Redis), password reset
   - Database: `auth_db` (PostgreSQL)

2. **Authorization Service** (Port 50052)
   - CEL-based policy evaluation, RBAC/ABAC enforcement
   - Permission caching in Redis
   - Database: `authz_db` (PostgreSQL)

3. **User Service** (Port 50053)
   - User CRUD, profile management, search
   - Database: `user_db` (PostgreSQL)

4. **IAM Admin Service** (Port 50054)
   - Role/policy CRUD, user-role assignments
   - Database: `iam_db` (PostgreSQL)

5. **Task Service** (Port 50055)
   - Task/project CRUD, assignments, status workflows
   - Database: `task_db` (PostgreSQL)

6. **Audit Service** (Port 50056)
   - Event logging, compliance reporting, metrics
   - Database: `audit_db` (TimescaleDB for time-series optimization)

7. **Notification Service** (Port 50057)
   - Email, webhooks, push notifications
   - Database: `notification_db` (PostgreSQL)

**Shared Libraries** (`taskman-v2/shared/pkg/`):
- `config/`: Configuration management
- `logger/`: Structured JSON logging (slog)
- `database/`: PostgreSQL connection pooling
- `cache/`: Redis client with circuit breakers
- `queue/`: RabbitMQ pub/sub with reliability patterns
- `jwt/`: JWT token generation/verification
- `middleware/`: gRPC middleware (logging, recovery, request_id)
- `health/`: Health check implementations
- `errors/`: Common error definitions

**Communication Patterns:**
- **Synchronous**: gRPC between services (with circuit breakers)
- **Asynchronous**: RabbitMQ topic exchanges for event-driven communication
  - Exchange pattern: `{service}.events` (e.g., `user.events`, `task.events`)
  - Dead Letter Queues (DLQ) for failed message handling

**Security:**
- JWT-based authentication (access tokens: 15 min, refresh tokens: 7 days)
- Multi-tenancy via `company_id` row-level isolation
- Environment-based secrets (no hardcoded credentials)
- Circuit breakers on all external dependencies (PostgreSQL, Redis, RabbitMQ)

### Frontend (taskman-frontend)

**Stack:**
- Next.js 15 with App Router
- TypeScript
- Tailwind CSS for styling
- Zustand for state management
- React Hook Form + Zod for form validation
- next-intl for internationalization

**Key Directories:**
- `src/app/`: Next.js app router pages
- `src/components/`: Reusable React components
- `src/lib/`: Utility functions and shared logic
- `src/store/`: Zustand state management stores

**API Communication:**
- Uses Next.js rewrites to proxy API calls to backend services
- Authentication state managed via Zustand
- JWT tokens stored securely (not in localStorage)

## Development Workflows

### Adding a New Microservice

1. Use existing service as template (e.g., `authentication-service`)
2. Create service directory structure:
   ```
   services/new-service/
   ├── api/                 # Protobuf definitions
   ├── cmd/
   │   ├── server/         # gRPC server entrypoint
   │   ├── http-server/    # HTTP REST API (optional)
   │   └── migrate/        # Database migration runner
   ├── internal/
   │   ├── service/        # Business logic
   │   └── storage/        # Database layer
   ├── migrations/         # SQL migration files
   ├── buf.yaml           # Buf protobuf config
   ├── buf.gen.yaml       # Buf code generation config
   ├── Dockerfile
   ├── Makefile
   └── go.mod
   ```
3. Define protobuf API in `api/*.proto`
4. Run `buf generate` to generate gRPC code
5. Implement service logic in `internal/service/`
6. Add database migrations in `migrations/`
7. Update root `Makefile` to include new service

### Running Integration Tests

```bash
# Debug RabbitMQ connections
./debug-rabbitmq.sh

# Test integrated platform
./test-integration.sh
```

### Working with Protobuf

```bash
# Generate Go code from .proto files
cd services/<service-name>
buf generate

# Validate proto files
buf lint

# Update dependencies
buf dep update
```

### Database Operations

**Connection Strings:**
- Auth DB: `postgresql://auth_user:auth_password_dev@localhost:5432/auth_db?sslmode=disable`
- All passwords follow pattern: `{service}_password_dev` for development

**Migration Pattern:**
Each service manages its own migrations in `migrations/` directory:
- `001_initial.up.sql` - Create tables
- `001_initial.down.sql` - Rollback

### Working with Docker Compose

```bash
# View logs for specific service
docker-compose -f docker-compose.dev.yml logs -f postgres

# Restart specific service
docker-compose -f docker-compose.dev.yml restart authentication-service

# Check service health
docker-compose -f docker-compose.dev.yml ps
```

## Important Patterns & Conventions

### Error Handling
```go
// Use shared error types from taskman-v2/shared/pkg/errors
return nil, errors.NewNotFoundError("user", userID)
return nil, errors.NewPermissionDeniedError("insufficient permissions")
```

### Logging
```go
// Use structured logging with slog
logger.Info("user created",
    slog.String("user_id", userID),
    slog.String("email", email))

logger.Error("database error",
    slog.String("operation", "insert"),
    slog.Any("error", err))
```

### Circuit Breakers
All external dependencies (DB, Redis, RabbitMQ) use circuit breakers via `gobreaker` package:
- MaxRequests: 3
- Interval: 1 minute
- Timeout: 30 seconds

### Multi-Tenancy
Every database query must filter by `company_id`:
```go
query := `SELECT * FROM users WHERE id = $1 AND company_id = $2`
```

### JWT Claims Structure
```go
type Claims struct {
    UserID    string   `json:"sub"`
    Email     string   `json:"email"`
    Username  string   `json:"username"`
    CompanyID string   `json:"company_id"`
    Roles     []string `json:"roles"`
    SessionID string   `json:"session_id"`
}
```

## Environment Variables

**Required for all services:**
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_ADDR` - Redis address (default: localhost:6379)
- `REDIS_PASSWORD` - Redis password
- `RABBITMQ_URI` - RabbitMQ connection URI
- `JWT_ACCESS_SECRET` - JWT signing secret (min 32 chars)
- `JWT_REFRESH_SECRET` - Refresh token signing secret (min 32 chars)

**Service-specific:**
- `HTTP_PORT` - HTTP server port (default: 8080)
- `GRPC_PORT` - gRPC server port (service-specific)

## Infrastructure Access

When running `make dev`, these services are available:
- **RabbitMQ Management**: http://localhost:15672 (taskman/taskman_dev_password)
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## Key Files

- `taskman-v2/ARCHITECTURE.md` - Detailed architecture documentation
- `taskman-v2/README.md` - Service inventory and deployment info
- `taskman-v2/Makefile` - Build and deployment commands
- `docker-compose.yml` - Main infrastructure setup
- `docker-compose.dev.yml` - Development environment (if exists)

## Known Issues & Gotcases

1. **Windows Development**: Use Git Bash or WSL for running shell scripts
2. **Port Conflicts**: Ensure ports 5432, 6379, 5672, 15672, 8080, 50051+ are available
3. **Database Initialization**: Run migrations before starting services
4. **JWT Secrets**: Must be at least 32 characters for security
5. **RabbitMQ Startup**: Can take 30-60s to be healthy after docker-compose up

## Testing Philosophy

- Unit tests for business logic in `internal/service/`
- Integration tests use Testcontainers for PostgreSQL/Redis/RabbitMQ
- gRPC integration tests for service contracts
- Target: 80%+ code coverage per service

## Build Artifacts

- Compiled binaries: `taskman-v2/bin/`
- Docker images: Tagged as `taskman-v2/{service-name}:latest`
- Proto-generated code: `services/{service}/pkg/api/api/`
