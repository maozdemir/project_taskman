@echo off
setlocal enabledelayedexpansion

REM TaskMan Integrated Platform Setup Script (Windows)
REM This script sets up the complete TaskMan platform with all services integrated

echo.
echo 🚀 TaskMan Integrated Platform Setup
echo ====================================
echo.

REM Check if Docker and Docker Compose are installed
echo [INFO] Checking prerequisites...

docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker first.
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not installed. Please install Docker Compose first.
    exit /b 1
)

echo [SUCCESS] Prerequisites check passed
echo.

REM Create necessary directories
echo [INFO] Creating necessary directories...
mkdir db\init 2>nul
mkdir logs 2>nul
mkdir monitoring\prometheus\rules 2>nul
mkdir monitoring\grafana\provisioning\datasources 2>nul
mkdir monitoring\grafana\provisioning\dashboards 2>nul
mkdir monitoring\grafana\dashboards 2>nul
echo [SUCCESS] Directories created
echo.

REM Generate environment file if it doesn't exist
if not exist .env (
    echo [INFO] Generating environment configuration...
    (
        echo # TaskMan Platform Environment Configuration
        echo COMPOSE_PROJECT_NAME=taskman
        echo.
        echo # Database Configuration
        echo POSTGRES_DB=taskman
        echo POSTGRES_USER=taskman
        echo POSTGRES_PASSWORD=taskman_dev_password
        echo.
        echo # Redis Configuration
        echo REDIS_PASSWORD=
        echo.
        echo # RabbitMQ Configuration
        echo RABBITMQ_DEFAULT_USER=taskman
        echo RABBITMQ_DEFAULT_PASS=taskman_dev_password
        echo.
        echo # JWT Configuration (CHANGE IN PRODUCTION!)
        echo JWT_ACCESS_SECRET=your-super-secret-access-key-change-in-production
        echo JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-in-production
        echo.
        echo # Grafana Configuration
        echo GF_SECURITY_ADMIN_PASSWORD=admin
        echo.
        echo # Logging
        echo LOG_LEVEL=info
        echo LOG_FORMAT=json
        echo.
        echo # Development flags
        echo DEBUG=false
        echo NODE_ENV=development
    ) > .env
    echo [SUCCESS] Environment file created
) else (
    echo [WARNING] Environment file already exists, skipping...
)
echo.

REM Check command line arguments
if "%1"=="--restart" (
    echo [INFO] Restarting TaskMan platform...
    docker-compose -f docker-compose.unified.yml down
    docker-compose -f docker-compose.unified.yml up -d
    echo [SUCCESS] Platform restarted
    goto :end
)

if "%1"=="--stop" (
    echo [INFO] Stopping TaskMan platform...
    docker-compose -f docker-compose.unified.yml down
    echo [SUCCESS] Platform stopped
    goto :end
)

if "%1"=="--clean" (
    echo [WARNING] This will remove all containers, volumes, and data. Are you sure? (y/N)
    set /p response=
    if /i "!response!"=="y" (
        docker-compose -f docker-compose.unified.yml down -v --remove-orphans
        docker system prune -f
        echo [SUCCESS] Platform cleaned
    ) else (
        echo [INFO] Clean operation cancelled
    )
    goto :end
)

REM Main setup flow
echo [INFO] Starting TaskMan Integrated Platform...
echo.

echo [INFO] Starting infrastructure services...
docker-compose -f docker-compose.unified.yml up -d postgres redis rabbitmq

echo [INFO] Waiting for infrastructure services to be ready...
timeout /t 30 /nobreak >nul

echo [INFO] Starting application services...
docker-compose -f docker-compose.unified.yml up -d authorization-service audit-service-go

echo [INFO] Starting monitoring services...
docker-compose -f docker-compose.unified.yml up -d prometheus grafana node-exporter cadvisor

echo [INFO] Starting load balancer...
docker-compose -f docker-compose.unified.yml up -d nginx

echo.
echo [INFO] Verifying all services...
docker-compose -f docker-compose.unified.yml ps

echo.
echo 🎉 TaskMan Platform is now running!
echo ==================================
echo.
echo 📊 Service URLs:
echo   • Main API Gateway:     http://localhost
echo   • Authorization API:    http://localhost/api/v1/auth/
echo   • Audit API:           http://localhost/api/v1/audit/
echo   • System Health:       http://localhost/health
echo.
echo 🔧 Management Interfaces:
echo   • Grafana Dashboard:   http://localhost:3000 (admin/admin)
echo   • Prometheus:          http://localhost:9090
echo   • RabbitMQ Management: http://localhost:15672 (taskman/taskman_dev_password)
echo.
echo 🔍 Service Health Checks:
echo   • Authorization:       http://localhost/health/auth
echo   • Audit:              http://localhost/health/audit
echo.
echo 📈 Metrics Endpoints:
echo   • Authorization:       http://localhost:8080/metrics
echo   • Audit:              http://localhost:9093/metrics
echo   • System Metrics:     http://localhost:9100/metrics
echo   • Container Metrics:  http://localhost:8082/metrics
echo.
echo 🛠  Useful Commands:
echo   • View logs:          docker-compose -f docker-compose.unified.yml logs -f [service]
echo   • Stop all:           docker-compose -f docker-compose.unified.yml down
echo   • Restart service:    docker-compose -f docker-compose.unified.yml restart [service]
echo.

:end
pause