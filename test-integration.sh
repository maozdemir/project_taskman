#!/bin/bash

# TaskMan Integration Test Script
# This script tests the integrated platform to ensure all services work together

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"

    TESTS_RUN=$((TESTS_RUN + 1))
    print_status "Running: $test_name"

    if eval "$test_command"; then
        if [ -n "$expected_result" ]; then
            if [[ "$test_command" == *"$expected_result"* ]]; then
                print_success "$test_name"
                TESTS_PASSED=$((TESTS_PASSED + 1))
            else
                print_error "$test_name (unexpected result)"
                TESTS_FAILED=$((TESTS_FAILED + 1))
            fi
        else
            print_success "$test_name"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        fi
    else
        print_error "$test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Function to check if service is responding
check_service() {
    local service_name="$1"
    local url="$2"
    local max_attempts=30
    local attempt=1

    print_status "Checking $service_name availability..."

    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$url" > /dev/null 2>&1; then
            print_success "$service_name is responding"
            return 0
        fi

        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    print_error "$service_name is not responding after $((max_attempts * 2)) seconds"
    return 1
}

echo "🧪 TaskMan Integration Tests"
echo "=========================="
echo ""

# Test 1: Check if Docker Compose file is valid
run_test "Docker Compose Configuration" \
    "docker-compose -f docker-compose.unified.yml config --quiet" \
    ""

echo ""
print_status "Starting integration tests..."
print_status "This will test the complete TaskMan platform integration"
echo ""

# Test 2: Check if all expected services are defined
print_status "Verifying service definitions..."
services=(
    "postgres"
    "redis"
    "rabbitmq"
    "authorization-service"
    "audit-service-go"
    "nginx"
    "prometheus"
    "grafana"
)

for service in "${services[@]}"; do
    if docker-compose -f docker-compose.unified.yml config | grep -q "^  $service:"; then
        print_success "Service '$service' is defined"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "Service '$service' is not defined"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
done

echo ""

# Test 3: Check nginx configuration
print_status "Testing nginx configuration..."
if [ -f "taskman-backend/services/nginx/nginx.conf" ]; then
    if grep -q "audit-service-go" taskman-backend/services/nginx/nginx.conf; then
        print_success "Nginx configured for Go audit service"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "Nginx not configured for Go audit service"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
fi

# Test 4: Check Prometheus configuration
print_status "Testing Prometheus configuration..."
if [ -f "monitoring/prometheus/prometheus.yml" ]; then
    if grep -q "audit-service-go" monitoring/prometheus/prometheus.yml; then
        print_success "Prometheus configured to scrape Go audit service"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "Prometheus not configured to scrape Go audit service"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
fi

echo ""

# Test 5: Check if we can build the services (optional - takes time)
if [ "$1" = "--build-test" ]; then
    print_status "Testing service builds (this may take a few minutes)..."

    if [ -d "taskman-backend/services/authorization-service" ]; then
        run_test "Authorization Service Build" \
            "cd taskman-backend/services/authorization-service && docker build -t test-auth-service:latest ." \
            ""
    fi

    if [ -d "taskman-backend/services/audit-service-go" ]; then
        run_test "Audit Service Build" \
            "cd taskman-backend/services/audit-service-go && docker build -t test-audit-service:latest ." \
            ""
    fi
fi

# Test 6: Quick network and volume checks
print_status "Testing Docker resources..."

# Check if we can create the network
run_test "Docker Network Creation" \
    "docker network ls | grep -q taskman || docker network create taskman-test-network" \
    ""

# Clean up test network
docker network rm taskman-test-network 2>/dev/null || true

echo ""

# Test 7: Check file permissions (Linux/macOS)
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "win32" ]]; then
    print_status "Checking file permissions..."

    if [ -f "setup-integrated-platform.sh" ]; then
        if [ -x "setup-integrated-platform.sh" ]; then
            print_success "Setup script is executable"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            print_error "Setup script is not executable"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
        TESTS_RUN=$((TESTS_RUN + 1))
    fi
fi

# Test 8: Live integration test (optional)
if [ "$1" = "--live-test" ]; then
    print_status "Running live integration test..."
    print_status "This will start the platform and test actual service endpoints"

    # Start the platform
    print_status "Starting TaskMan platform..."
    docker-compose -f docker-compose.unified.yml up -d

    # Wait for services to be ready
    sleep 60

    # Test service endpoints
    check_service "NGINX Load Balancer" "http://localhost/health"
    check_service "Grafana Dashboard" "http://localhost:3000"
    check_service "Prometheus Metrics" "http://localhost:9090"
    check_service "RabbitMQ Management" "http://localhost:15672"

    # Test API endpoints through nginx
    check_service "Authorization Service via NGINX" "http://localhost/health/auth"
    check_service "Audit Service via NGINX" "http://localhost/health/audit"

    # Clean up
    print_status "Cleaning up test environment..."
    docker-compose -f docker-compose.unified.yml down
fi

echo ""
echo "📊 Test Results Summary"
echo "======================"
echo "Total tests run: $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"

if [ $TESTS_FAILED -eq 0 ]; then
    print_success "All tests passed! 🎉"
    echo ""
    echo "✅ The TaskMan integrated platform is ready to deploy!"
    echo "   Run './setup-integrated-platform.sh' to start all services"
    exit 0
else
    print_error "Some tests failed! ❌"
    echo ""
    echo "Please review the failed tests and fix the issues before deployment."
    echo ""
    echo "Common fixes:"
    echo "• Make sure all files exist in the correct locations"
    echo "• Check file permissions (run 'chmod +x setup-integrated-platform.sh')"
    echo "• Verify Docker and Docker Compose are installed and running"
    echo "• Review the docker-compose.unified.yml file for syntax errors"
    exit 1
fi