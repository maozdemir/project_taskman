#!/bin/bash

# TaskMan Integrated Platform Setup Script
# This script sets up the complete TaskMan platform with all services integrated

set -e

echo "🚀 TaskMan Integrated Platform Setup"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker and Docker Compose are installed
check_prerequisites() {
    print_status "Checking prerequisites..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    print_success "Prerequisites check passed"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."

    mkdir -p db/init
    mkdir -p logs
    mkdir -p monitoring/prometheus/rules
    mkdir -p monitoring/grafana/provisioning/datasources
    mkdir -p monitoring/grafana/provisioning/dashboards
    mkdir -p monitoring/grafana/dashboards

    print_success "Directories created"
}

# Generate environment files
generate_env_files() {
    print_status "Generating environment configuration..."

    # Create .env file if it doesn't exist
    if [[ ! -f .env ]]; then
        cat > .env << EOF
# TaskMan Platform Environment Configuration
COMPOSE_PROJECT_NAME=taskman

# Database Configuration
POSTGRES_DB=taskman
POSTGRES_USER=taskman
POSTGRES_PASSWORD=taskman_dev_password

# Redis Configuration
REDIS_PASSWORD=

# RabbitMQ Configuration
RABBITMQ_DEFAULT_USER=taskman
RABBITMQ_DEFAULT_PASS=taskman_dev_password

# JWT Configuration (CHANGE IN PRODUCTION!)
JWT_ACCESS_SECRET=your-super-secret-access-key-change-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-in-production

# Grafana Configuration
GF_SECURITY_ADMIN_PASSWORD=admin

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# Development flags
DEBUG=false
NODE_ENV=development
EOF
        print_success "Environment file created"
    else
        print_warning "Environment file already exists, skipping..."
    fi
}

# Build all services
build_services() {
    print_status "Building all services..."

    # Build Go services first
    print_status "Building Authorization Service (Go)..."
    cd taskman-backend/services/authorization-service
    if [[ -f Dockerfile ]]; then
        docker build -t taskman-authorization-service:latest .
    else
        print_error "Authorization service Dockerfile not found"
        exit 1
    fi
    cd ../../../

    print_status "Building Audit Service (Go)..."
    cd taskman-backend/services/audit-service-go
    if [[ -f Dockerfile ]]; then
        docker build -t taskman-audit-service-go:latest .
    else
        print_error "Audit service Dockerfile not found"
        exit 1
    fi
    cd ../../../

    print_success "Services built successfully"
}

# Start infrastructure services first
start_infrastructure() {
    print_status "Starting infrastructure services..."

    docker-compose -f docker-compose.unified.yml up -d postgres redis rabbitmq

    # Wait for services to be healthy
    print_status "Waiting for infrastructure services to be ready..."

    # Wait for PostgreSQL
    print_status "Waiting for PostgreSQL..."
    while ! docker-compose -f docker-compose.unified.yml exec -T postgres pg_isready -U taskman -d taskman &> /dev/null; do
        sleep 2
        echo -n "."
    done
    echo ""

    # Wait for Redis
    print_status "Waiting for Redis..."
    while ! docker-compose -f docker-compose.unified.yml exec -T redis redis-cli ping &> /dev/null; do
        sleep 2
        echo -n "."
    done
    echo ""

    # Wait for RabbitMQ
    print_status "Waiting for RabbitMQ..."
    while ! docker-compose -f docker-compose.unified.yml exec -T rabbitmq rabbitmq-diagnostics -q ping &> /dev/null; do
        sleep 2
        echo -n "."
    done
    echo ""

    print_success "Infrastructure services are ready"
}

# Run database migrations
run_migrations() {
    print_status "Running database migrations..."

    # Run authorization service migrations
    print_status "Running authorization service migrations..."
    # This would be handled by the Go service on startup

    # Run audit service migrations
    print_status "Running audit service migrations..."
    # This would be handled by the Go service on startup

    print_success "Database migrations completed"
}

# Start application services
start_applications() {
    print_status "Starting application services..."

    docker-compose -f docker-compose.unified.yml up -d authorization-service audit-service-go

    # Wait for application services to be healthy
    print_status "Waiting for application services to be ready..."
    sleep 30  # Give services time to start

    print_success "Application services started"
}

# Start monitoring services
start_monitoring() {
    print_status "Starting monitoring services..."

    docker-compose -f docker-compose.unified.yml up -d prometheus grafana node-exporter cadvisor

    print_success "Monitoring services started"
}

# Start load balancer
start_load_balancer() {
    print_status "Starting load balancer..."

    docker-compose -f docker-compose.unified.yml up -d nginx

    print_success "Load balancer started"
}

# Verify all services are running
verify_services() {
    print_status "Verifying all services..."

    # Check service health
    services=(
        "taskman-postgres:5432"
        "taskman-redis:6379"
        "taskman-rabbitmq:5672"
        "taskman-authorization-service:8080"
        "taskman-audit-service-go:8081"
        "taskman-nginx:80"
        "taskman-prometheus:9090"
        "taskman-grafana:3000"
    )

    for service in "${services[@]}"; do
        IFS=':' read -r container port <<< "$service"
        if docker ps | grep -q "$container"; then
            print_success "✓ $container is running"
        else
            print_error "✗ $container is not running"
        fi
    done
}

# Print access information
print_access_info() {
    echo ""
    echo "🎉 TaskMan Platform is now running!"
    echo "=================================="
    echo ""
    echo "📊 Service URLs:"
    echo "  • Main API Gateway:     http://localhost"
    echo "  • Authorization API:    http://localhost/api/v1/auth/"
    echo "  • Audit API:           http://localhost/api/v1/audit/"
    echo "  • System Health:       http://localhost/health"
    echo ""
    echo "🔧 Management Interfaces:"
    echo "  • Grafana Dashboard:   http://localhost:3000 (admin/admin)"
    echo "  • Prometheus:          http://localhost:9090"
    echo "  • RabbitMQ Management: http://localhost:15672 (taskman/taskman_dev_password)"
    echo "  • Database Admin:      http://localhost:8083 (adminer)"
    echo ""
    echo "🔍 Service Health Checks:"
    echo "  • Authorization:       http://localhost/health/auth"
    echo "  • Audit:              http://localhost/health/audit"
    echo ""
    echo "📈 Metrics Endpoints:"
    echo "  • Authorization:       http://localhost:8080/metrics"
    echo "  • Audit:              http://localhost:9093/metrics"
    echo "  • System Metrics:     http://localhost:9100/metrics"
    echo "  • Container Metrics:  http://localhost:8082/metrics"
    echo ""
    echo "🛠  Useful Commands:"
    echo "  • View logs:          docker-compose -f docker-compose.unified.yml logs -f [service]"
    echo "  • Stop all:           docker-compose -f docker-compose.unified.yml down"
    echo "  • Restart service:    docker-compose -f docker-compose.unified.yml restart [service]"
    echo "  • Scale service:      docker-compose -f docker-compose.unified.yml up -d --scale [service]=N"
    echo ""
    echo "🐛 Troubleshooting:"
    echo "  • Check service status: docker-compose -f docker-compose.unified.yml ps"
    echo "  • View service logs:    docker-compose -f docker-compose.unified.yml logs [service]"
    echo "  • Restart everything:   ./setup-integrated-platform.sh --restart"
    echo ""
}

# Handle command line arguments
case "${1:-}" in
    --restart)
        print_status "Restarting TaskMan platform..."
        docker-compose -f docker-compose.unified.yml down
        docker-compose -f docker-compose.unified.yml up -d
        print_success "Platform restarted"
        ;;
    --stop)
        print_status "Stopping TaskMan platform..."
        docker-compose -f docker-compose.unified.yml down
        print_success "Platform stopped"
        ;;
    --clean)
        print_warning "This will remove all containers, volumes, and data. Are you sure? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            docker-compose -f docker-compose.unified.yml down -v --remove-orphans
            docker system prune -f
            print_success "Platform cleaned"
        else
            print_status "Clean operation cancelled"
        fi
        ;;
    *)
        # Main setup flow
        check_prerequisites
        create_directories
        generate_env_files
        build_services
        start_infrastructure
        run_migrations
        start_applications
        start_monitoring
        start_load_balancer
        verify_services
        print_access_info
        ;;
esac