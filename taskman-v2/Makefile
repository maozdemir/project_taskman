.PHONY: help install dev up down logs clean test lint proto build docker-build k8s-deploy

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo '$(BLUE)TaskMan v2 - Military-Grade Microservices$(NC)'
	@echo ''
	@echo 'Usage:'
	@echo '  $(GREEN)make$(NC) $(BLUE)<target>$(NC)'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	@command -v go >/dev/null 2>&1 || { echo "$(RED)Go is not installed$(NC)"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)Docker is not installed$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo "$(RED)Docker Compose is not installed$(NC)"; exit 1; }
	@echo "$(GREEN)Installing Go tools...$(NC)"
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/vektra/mockery/v2@latest
	@echo "$(GREEN)Installing buf for proto management...$(NC)"
	go install github.com/bufbuild/buf/cmd/buf@latest
	@echo "$(GREEN)Done!$(NC)"

setup: ## Initial setup (copy .env, create directories)
	@echo "$(BLUE)Setting up TaskMan v2...$(NC)"
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)Created .env file from .env.example$(NC)"; \
		echo "$(RED)⚠️  Please update .env with your configuration!$(NC)"; \
	else \
		echo "$(GREEN).env file already exists$(NC)"; \
	fi
	@echo "$(GREEN)Setup complete!$(NC)"

dev: setup ## Start development environment
	@echo "$(BLUE)Starting development environment...$(NC)"
	docker-compose -f docker-compose.dev.yml up -d
	@echo "$(GREEN)Development environment started!$(NC)"
	@echo ""
	@echo "$(BLUE)Services:$(NC)"
	@echo "  RabbitMQ Management: http://localhost:15672"
	@echo "  Prometheus:          http://localhost:9090"
	@echo "  Grafana:             http://localhost:3000"
	@echo "  Jaeger UI:           http://localhost:16686"
	@echo "  Kong Admin:          http://localhost:8001"
	@echo "  Kong Manager:        http://localhost:8002"
	@echo "  Vault:               http://localhost:8200"
	@echo "  MailHog:             http://localhost:8025"

up: dev ## Alias for 'dev'

down: ## Stop development environment
	@echo "$(BLUE)Stopping development environment...$(NC)"
	docker-compose -f docker-compose.dev.yml down
	@echo "$(GREEN)Stopped!$(NC)"

logs: ## Show logs from all containers
	docker-compose -f docker-compose.dev.yml logs -f

logs-service: ## Show logs for a specific service (usage: make logs-service SERVICE=postgres-auth)
	@if [ -z "$(SERVICE)" ]; then \
		echo "$(RED)Please specify SERVICE=<service-name>$(NC)"; \
		exit 1; \
	fi
	docker-compose -f docker-compose.dev.yml logs -f $(SERVICE)

clean: ## Clean up containers, volumes, and build artifacts
	@echo "$(RED)Cleaning up...$(NC)"
	docker-compose -f docker-compose.dev.yml down -v
	find . -name "*.test" -delete
	find . -name "coverage.out" -delete
	rm -rf dist/
	@echo "$(GREEN)Cleaned!$(NC)"

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	cd shared && go test -v -race -coverprofile=coverage.out ./...
	cd services/authentication-service && go test -v -race -coverprofile=coverage.out ./...
	cd services/authorization-service && go test -v -race -coverprofile=coverage.out ./...
	cd services/user-service && go test -v -race -coverprofile=coverage.out ./...
	cd services/iam-admin-service && go test -v -race -coverprofile=coverage.out ./...
	cd services/task-service && go test -v -race -coverprofile=coverage.out ./...
	cd services/audit-service && go test -v -race -coverprofile=coverage.out ./...
	cd services/notification-service && go test -v -race -coverprofile=coverage.out ./...
	@echo "$(GREEN)Tests passed!$(NC)"

test-coverage: test ## Run tests with coverage report
	@echo "$(BLUE)Generating coverage report...$(NC)"
	go tool cover -html=shared/coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report: coverage.html$(NC)"

lint: ## Run linters
	@echo "$(BLUE)Running linters...$(NC)"
	cd shared && golangci-lint run ./...
	cd services/authentication-service && golangci-lint run ./...
	cd services/authorization-service && golangci-lint run ./...
	cd services/user-service && golangci-lint run ./...
	cd services/iam-admin-service && golangci-lint run ./...
	cd services/task-service && golangci-lint run ./...
	cd services/audit-service && golangci-lint run ./...
	cd services/notification-service && golangci-lint run ./...
	@echo "$(GREEN)Linting passed!$(NC)"

proto: ## Generate code from proto files
	@echo "$(BLUE)Generating protobuf code...$(NC)"
	cd services/authentication-service && buf generate
	cd services/authorization-service && buf generate
	cd services/user-service && buf generate
	cd services/iam-admin-service && buf generate
	cd services/task-service && buf generate
	cd services/audit-service && buf generate
	cd services/notification-service && buf generate
	@echo "$(GREEN)Proto generation complete!$(NC)"

build: ## Build all services
	@echo "$(BLUE)Building services...$(NC)"
	cd services/authentication-service && go build -o ../../bin/authentication-service ./cmd/server
	cd services/authorization-service && go build -o ../../bin/authorization-service ./cmd/server
	cd services/user-service && go build -o ../../bin/user-service ./cmd/server
	cd services/iam-admin-service && go build -o ../../bin/iam-admin-service ./cmd/server
	cd services/task-service && go build -o ../../bin/task-service ./cmd/server
	cd services/audit-service && go build -o ../../bin/audit-service ./cmd/server
	cd services/notification-service && go build -o ../../bin/notification-service ./cmd/server
	@echo "$(GREEN)Build complete! Binaries in ./bin/$(NC)"

docker-build: ## Build Docker images for all services
	@echo "$(BLUE)Building Docker images...$(NC)"
	docker build -t taskman-v2/authentication-service:latest -f services/authentication-service/Dockerfile services/authentication-service
	docker build -t taskman-v2/authorization-service:latest -f services/authorization-service/Dockerfile services/authorization-service
	docker build -t taskman-v2/user-service:latest -f services/user-service/Dockerfile services/user-service
	docker build -t taskman-v2/iam-admin-service:latest -f services/iam-admin-service/Dockerfile services/iam-admin-service
	docker build -t taskman-v2/task-service:latest -f services/task-service/Dockerfile services/task-service
	docker build -t taskman-v2/audit-service:latest -f services/audit-service/Dockerfile services/audit-service
	docker build -t taskman-v2/notification-service:latest -f services/notification-service/Dockerfile services/notification-service
	@echo "$(GREEN)Docker images built!$(NC)"

migrate-up: ## Run database migrations up
	@echo "$(BLUE)Running migrations...$(NC)"
	cd services/authentication-service && go run cmd/migrate/main.go up
	cd services/authorization-service && go run cmd/migrate/main.go up
	cd services/user-service && go run cmd/migrate/main.go up
	cd services/iam-admin-service && go run cmd/migrate/main.go up
	cd services/task-service && go run cmd/migrate/main.go up
	cd services/audit-service && go run cmd/migrate/main.go up
	cd services/notification-service && go run cmd/migrate/main.go up
	@echo "$(GREEN)Migrations complete!$(NC)"

migrate-down: ## Run database migrations down
	@echo "$(RED)Rolling back migrations...$(NC)"
	cd services/authentication-service && go run cmd/migrate/main.go down
	cd services/authorization-service && go run cmd/migrate/main.go down
	cd services/user-service && go run cmd/migrate/main.go down
	cd services/iam-admin-service && go run cmd/migrate/main.go down
	cd services/task-service && go run cmd/migrate/main.go down
	cd services/audit-service && go run cmd/migrate/main.go down
	cd services/notification-service && go run cmd/migrate/main.go down
	@echo "$(GREEN)Rollback complete!$(NC)"

k8s-deploy: ## Deploy to Kubernetes
	@echo "$(BLUE)Deploying to Kubernetes...$(NC)"
	kubectl apply -f k8s/base/
	kubectl apply -f k8s/infrastructure/
	kubectl apply -f k8s/services/
	@echo "$(GREEN)Deployed to Kubernetes!$(NC)"

k8s-delete: ## Delete Kubernetes resources
	@echo "$(RED)Deleting Kubernetes resources...$(NC)"
	kubectl delete -f k8s/services/
	kubectl delete -f k8s/infrastructure/
	kubectl delete -f k8s/base/
	@echo "$(GREEN)Deleted!$(NC)"

vault-init: ## Initialize Vault with secrets
	@echo "$(BLUE)Initializing Vault...$(NC)"
	./scripts/vault-init.sh
	@echo "$(GREEN)Vault initialized!$(NC)"

kong-config: ## Configure Kong API Gateway
	@echo "$(BLUE)Configuring Kong...$(NC)"
	./scripts/kong-config.sh
	@echo "$(GREEN)Kong configured!$(NC)"

benchmark: ## Run performance benchmarks
	@echo "$(BLUE)Running benchmarks...$(NC)"
	cd services/authorization-service && go test -bench=. -benchmem ./...
	@echo "$(GREEN)Benchmarks complete!$(NC)"

security-scan: ## Run security scans
	@echo "$(BLUE)Running security scans...$(NC)"
	docker run --rm -v $(PWD):/src aquasec/trivy:latest fs --severity HIGH,CRITICAL /src
	@echo "$(GREEN)Security scan complete!$(NC)"

docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	@echo "$(GREEN)Documentation generated!$(NC)"

.DEFAULT_GOAL := help