# iam-admin-service

## Description

[Service description]

## API

See `api/*.proto` for gRPC definitions.

## Configuration

Environment variables:
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_ADDR` - Redis address
- `RABBITMQ_URI` - RabbitMQ URI
- `GRPC_PORT` - gRPC port (default: 50054)
- `METRICS_PORT` - Metrics port (default: 9094)

## Development

```bash
# Install dependencies
go mod download

# Generate proto
make proto

# Run tests
make test

# Run service
make run
```

## Deployment

```bash
# Build Docker image
make docker-build

# Run migrations
make migrate-up
```
