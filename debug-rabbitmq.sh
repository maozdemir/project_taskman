#!/bin/bash

# RabbitMQ Debug and Test Script for TaskMan Platform
# This script helps debug RabbitMQ connectivity and configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
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

echo "🐰 RabbitMQ Debug and Test Script"
echo "================================="
echo ""

# Test 1: Check if RabbitMQ container is running
print_status "Checking RabbitMQ container status..."
if docker ps | grep -q taskman-rabbitmq; then
    print_success "RabbitMQ container is running"

    # Get container details
    CONTAINER_STATUS=$(docker ps --filter "name=taskman-rabbitmq" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}")
    echo "$CONTAINER_STATUS"
else
    print_error "RabbitMQ container is not running"
    echo ""
    print_status "Available containers:"
    docker ps
    exit 1
fi

echo ""

# Test 2: Check RabbitMQ logs for errors
print_status "Checking RabbitMQ logs for recent errors..."
RECENT_ERRORS=$(docker logs taskman-rabbitmq --since=10m 2>&1 | grep -i "error\|warn\|fail" | tail -5)

if [ -z "$RECENT_ERRORS" ]; then
    print_success "No recent errors found in RabbitMQ logs"
else
    print_warning "Recent errors/warnings found:"
    echo "$RECENT_ERRORS"
fi

echo ""

# Test 3: Check RabbitMQ management interface
print_status "Testing RabbitMQ management interface..."
if curl -f -s -u taskman:taskman_dev_password http://localhost:15672/api/overview > /dev/null 2>&1; then
    print_success "RabbitMQ management interface is accessible"

    # Get overview information
    OVERVIEW=$(curl -s -u taskman:taskman_dev_password http://localhost:15672/api/overview | jq -r '.rabbitmq_version, .erlang_version')
    echo "RabbitMQ Version: $(echo "$OVERVIEW" | head -1)"
    echo "Erlang Version: $(echo "$OVERVIEW" | tail -1)"
else
    print_error "RabbitMQ management interface is not accessible"
    print_status "Trying to check if port 15672 is open..."
    nc -zv localhost 15672 2>&1 || print_error "Port 15672 is not accessible"
fi

echo ""

# Test 4: Check virtual hosts
print_status "Checking virtual hosts..."
VHOSTS=$(curl -s -u taskman:taskman_dev_password http://localhost:15672/api/vhosts 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$VHOSTS" | jq -r '.[] | .name' | while read vhost; do
        print_success "Virtual host found: $vhost"
    done
else
    print_error "Failed to retrieve virtual hosts"
fi

echo ""

# Test 5: Check exchanges
print_status "Checking exchanges..."
EXCHANGES=$(curl -s -u taskman:taskman_dev_password http://localhost:15672/api/exchanges 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$EXCHANGES" | jq -r '.[] | select(.name != "") | .name' | while read exchange; do
        print_success "Exchange found: $exchange"
    done
else
    print_error "Failed to retrieve exchanges"
fi

echo ""

# Test 6: Check queues
print_status "Checking queues..."
QUEUES=$(curl -s -u taskman:taskman_dev_password http://localhost:15672/api/queues 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$QUEUES" | jq -r '.[] | .name' | while read queue; do
        MESSAGES=$(echo "$QUEUES" | jq -r ".[] | select(.name == \"$queue\") | .messages")
        print_success "Queue found: $queue (messages: $MESSAGES)"
    done
else
    print_error "Failed to retrieve queues"
fi

echo ""

# Test 7: Check connections
print_status "Checking active connections..."
CONNECTIONS=$(curl -s -u taskman:taskman_dev_password http://localhost:15672/api/connections 2>/dev/null)
if [ $? -eq 0 ]; then
    CONNECTION_COUNT=$(echo "$CONNECTIONS" | jq '. | length')
    print_success "Active connections: $CONNECTION_COUNT"

    if [ "$CONNECTION_COUNT" -gt 0 ]; then
        echo "$CONNECTIONS" | jq -r '.[] | "  - User: \(.user) from \(.peer_host):\(.peer_port)"'
    fi
else
    print_error "Failed to retrieve connections"
fi

echo ""

# Test 8: Check service configuration
print_status "Checking service configuration in docker-compose..."

if grep -q "rabbitmq" docker-compose.unified.yml; then
    print_success "RabbitMQ service is defined in docker-compose"

    # Check environment variables
    if grep -q "RABBITMQ_DEFAULT_USER.*taskman" docker-compose.unified.yml; then
        print_success "RabbitMQ user is configured correctly"
    else
        print_warning "RabbitMQ user configuration may be incorrect"
    fi

    # Check volume mounts
    if grep -q "rabbitmq.conf" docker-compose.unified.yml; then
        print_success "RabbitMQ config file is mounted"
    else
        print_warning "RabbitMQ config file mount not found"
    fi

    if grep -q "definitions.json" docker-compose.unified.yml; then
        print_success "RabbitMQ definitions file is mounted"
    else
        print_warning "RabbitMQ definitions file mount not found"
    fi
else
    print_error "RabbitMQ service not found in docker-compose"
fi

echo ""

# Test 9: Test basic message publishing and consuming
print_status "Testing basic message operations..."

# Publish a test message
TEST_MESSAGE='{"test": "message", "timestamp": "'$(date -Iseconds)'"}'
PUBLISH_RESULT=$(curl -s -u taskman:taskman_dev_password -X POST \
    -H "Content-Type: application/json" \
    -d "{\"properties\":{},\"routing_key\":\"test.message\",\"payload\":\"$TEST_MESSAGE\",\"payload_encoding\":\"string\"}" \
    http://localhost:15672/api/exchanges/%2F/taskman.events/publish 2>/dev/null)

if echo "$PUBLISH_RESULT" | jq -e '.routed' > /dev/null 2>&1; then
    print_success "Test message published successfully"
else
    print_warning "Failed to publish test message or message not routed"
    echo "Response: $PUBLISH_RESULT"
fi

echo ""

# Test 10: Check if audit service can connect to RabbitMQ
print_status "Testing audit service RabbitMQ configuration..."

# Check if audit service is running
if docker ps | grep -q audit-service-go; then
    print_success "Audit service container is running"

    # Check audit service logs for RabbitMQ connection
    RABBITMQ_LOGS=$(docker logs taskman-audit-service-go --since=5m 2>&1 | grep -i "rabbitmq\|amqp\|queue" | tail -3)

    if [ -n "$RABBITMQ_LOGS" ]; then
        print_status "Recent RabbitMQ-related logs from audit service:"
        echo "$RABBITMQ_LOGS"
    else
        print_warning "No recent RabbitMQ-related logs found in audit service"
    fi
else
    print_warning "Audit service container is not running"
fi

echo ""

# Test 11: Network connectivity test
print_status "Testing network connectivity..."

# Test from audit service to RabbitMQ
if docker ps | grep -q audit-service-go; then
    NETWORK_TEST=$(docker exec taskman-audit-service-go nc -z rabbitmq 5672 2>&1)
    if [ $? -eq 0 ]; then
        print_success "Network connectivity from audit service to RabbitMQ is working"
    else
        print_error "Network connectivity issue between audit service and RabbitMQ"
        echo "Network test result: $NETWORK_TEST"
    fi
fi

echo ""

# Test 12: Check Prometheus metrics
print_status "Testing RabbitMQ Prometheus metrics..."
if curl -f -s http://localhost:15692/metrics > /dev/null 2>&1; then
    print_success "RabbitMQ Prometheus metrics endpoint is accessible"

    # Get some key metrics
    METRICS=$(curl -s http://localhost:15692/metrics | grep -E "^rabbitmq_")
    METRIC_COUNT=$(echo "$METRICS" | wc -l)
    print_success "Available metrics: $METRIC_COUNT"
else
    print_warning "RabbitMQ Prometheus metrics endpoint is not accessible"
    print_status "This may be because the prometheus plugin is not enabled"
fi

echo ""

# Summary and recommendations
echo "📋 Debug Summary and Recommendations"
echo "=================================="

print_status "If you see any issues above, here are some common fixes:"
echo ""
echo "1. Container not running:"
echo "   docker-compose -f docker-compose.unified.yml up -d rabbitmq"
echo ""
echo "2. Management interface not accessible:"
echo "   - Check if port 15672 is properly exposed in docker-compose"
echo "   - Verify credentials: taskman/taskman_dev_password"
echo ""
echo "3. No exchanges/queues found:"
echo "   - Check if definitions.json is properly loaded"
echo "   - Restart RabbitMQ: docker-compose restart rabbitmq"
echo ""
echo "4. Service connection issues:"
echo "   - Check environment variables in docker-compose"
echo "   - Verify network connectivity between containers"
echo "   - Check service logs for detailed error messages"
echo ""
echo "5. Enable debug logging:"
echo "   docker-compose -f docker-compose.unified.yml logs -f rabbitmq"
echo "   docker-compose -f docker-compose.unified.yml logs -f audit-service-go"
echo ""

# Useful commands
echo "🛠  Useful RabbitMQ Commands"
echo "=========================="
echo ""
echo "• View RabbitMQ logs:"
echo "  docker-compose -f docker-compose.unified.yml logs rabbitmq"
echo ""
echo "• Restart RabbitMQ:"
echo "  docker-compose -f docker-compose.unified.yml restart rabbitmq"
echo ""
echo "• Access RabbitMQ shell:"
echo "  docker exec -it taskman-rabbitmq rabbitmqctl status"
echo ""
echo "• View queue statistics:"
echo "  curl -u taskman:taskman_dev_password http://localhost:15672/api/queues"
echo ""
echo "• Management UI:"
echo "  http://localhost:15672 (taskman/taskman_dev_password)"
echo ""
echo "• Prometheus metrics:"
echo "  http://localhost:15692/metrics"
echo ""

print_success "RabbitMQ debug completed!"