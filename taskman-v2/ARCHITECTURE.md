# TaskMan v2 - Architecture Documentation

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Architecture Principles](#architecture-principles)
3. [Service Boundaries](#service-boundaries)
4. [Data Architecture](#data-architecture)
5. [Communication Patterns](#communication-patterns)
6. [Security Architecture](#security-architecture)
7. [Observability](#observability)
8. [Deployment Strategy](#deployment-strategy)
9. [Migration from v1](#migration-from-v1)
10. [Design Decisions](#design-decisions)

## Executive Summary

TaskMan v2 is a complete architectural rebuild designed to address critical anti-patterns identified in v1:

**v1 Problems Fixed:**
- ❌ Shared database → ✅ Database per service
- ❌ God service (Authorization) → ✅ 8 specialized microservices
- ❌ Broken policy evaluator → ✅ CEL-based policy engine
- ❌ No circuit breakers → ✅ Resilience patterns throughout
- ❌ Tight coupling → ✅ Event-driven architecture
- ❌ Security vulnerabilities → ✅ Vault, mTLS, OAuth 2.0

**Target Metrics:**
- Availability: 99.9% (8.76 hours downtime/year)
- Latency: p99 < 200ms
- Throughput: 10,000 RPS
- Test Coverage: 80%+

## Architecture Principles

### 1. Single Responsibility Principle
Each service has ONE clear responsibility:
```
Authentication Service  → JWT tokens, sessions, login
Authorization Service   → Policy evaluation only
User Service           → User CRUD, profiles
IAM Admin Service      → Role/policy management
Task Service           → Task CRUD, workflows
Audit Service          → Event logging, compliance
Notification Service   → Email, webhooks, push
API Gateway            → Routing, rate limiting, WAF
```

### 2. Database per Service
```
Service                → Database
─────────────────────────────────────
authentication-service → auth_db
authorization-service  → authz_db
user-service          → user_db
iam-admin-service     → iam_db
task-service          → task_db
audit-service         → audit_db (TimescaleDB)
notification-service  → notification_db
```

**Why TimescaleDB for Audit?**
- Optimized for time-series data
- Automatic data retention policies
- Efficient compression
- Fast time-based queries

### 3. API Gateway Pattern

```
Client
  ↓
Kong API Gateway (Single Entry Point)
  ├─ Rate Limiting (per IP, per user, per endpoint)
  ├─ Authentication (JWT validation)
  ├─ Authorization (call authz service)
  ├─ Request Transformation
  ├─ Response Caching
  ├─ Circuit Breaking
  ├─ WAF (Web Application Firewall)
  └─ Analytics
  ↓
Backend Services (gRPC)
```

### 4. Event-Driven Architecture

**Exchanges (Topic):**
```
auth.events         → user.*, session.*
user.events         → user.created, user.updated, user.deleted
task.events         → task.*, project.*
iam.events          → role.*, policy.*
notification.events → email.*, webhook.*
```

**Dead Letter Queues:**
- Failed messages → DLX → DLQ
- Monitoring alerts on DLQ depth
- Manual intervention for DLQ processing

### 5. CQRS (Command Query Responsibility Segregation)

**Authorization Service:**
```
Write Side (Commands):
  ├─ Policy changes → PostgreSQL
  └─ Event published → RabbitMQ

Read Side (Queries):
  ├─ Check permission → Redis cache
  ├─ Cache miss → PostgreSQL + CEL evaluation
  └─ Cache result (TTL: 5 min)
```

**Benefits:**
- Fast reads (< 5ms from Redis)
- Scalable (read replicas)
- Resilient (cache fallback)

### 6. Circuit Breaker Pattern

```go
// Example: RabbitMQ with circuit breaker
breaker := gobreaker.NewCircuitBreaker(gobreaker.Settings{
    Name:        "RabbitMQ",
    MaxRequests: 3,
    Interval:    time.Minute,
    Timeout:     30 * time.Second,
    OnStateChange: func(name string, from, to gobreaker.State) {
        logger.Warn("Circuit breaker state changed",
            slog.String("name", name),
            slog.String("from", from.String()),
            slog.String("to", to.String()),
        )
    },
})

// Use circuit breaker
_, err := breaker.Execute(func() (interface{}, error) {
    return queue.PublishEvent(event)
})
```

**States:**
- **Closed**: Normal operation
- **Open**: Failing fast (no requests sent)
- **Half-Open**: Testing if service recovered

### 7. Service Mesh (Istio)

**Features:**
- **mTLS**: Automatic TLS between services
- **Traffic Management**: Canary deployments, A/B testing
- **Observability**: Distributed tracing, metrics
- **Security**: Network policies, RBAC

**Why Istio?**
- Industry standard
- Production-proven
- Rich ecosystem
- CNCF graduated project

## Service Boundaries

### Authentication Service

**Responsibility:** User authentication, session management

**API:**
```protobuf
service AuthenticationService {
  rpc Login(LoginRequest) returns (LoginResponse);
  rpc Logout(LogoutRequest) returns (LogoutResponse);
  rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
  rpc VerifyToken(VerifyTokenRequest) returns (VerifyTokenResponse);
  rpc ResetPassword(ResetPasswordRequest) returns (ResetPasswordResponse);
}
```

**Database Schema:**
```sql
TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  refresh_token VARCHAR(512) NOT NULL,
  ip_address INET,
  user_agent TEXT,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  INDEX idx_sessions_user_id (user_id),
  INDEX idx_sessions_expires (expires_at)
);

TABLE password_resets (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  token VARCHAR(512) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);
```

**Events Published:**
- `auth.login.success`
- `auth.login.failed`
- `auth.logout`
- `auth.token.refreshed`
- `auth.password.reset`

### Authorization Service

**Responsibility:** Policy evaluation only

**API:**
```protobuf
service AuthorizationService {
  rpc Check(CheckRequest) returns (CheckResponse);
  rpc BatchCheck(BatchCheckRequest) returns (BatchCheckResponse);
}

message CheckRequest {
  string subject = 1;   // user:123
  string action = 2;    // tasks:edit
  string resource = 3;  // tasks/456
  map<string, string> context = 4;  // department, location, etc.
}

message CheckResponse {
  bool allowed = 1;
  repeated string reasons = 2;
}
```

**Database Schema:**
```sql
TABLE policies (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  effect VARCHAR(10) NOT NULL, -- 'allow' or 'deny'
  actions TEXT[] NOT NULL,
  resources TEXT[] NOT NULL,
  condition TEXT, -- CEL expression
  company_id UUID NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

TABLE roles (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  company_id UUID NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

TABLE role_policies (
  role_id UUID REFERENCES roles(id),
  policy_id UUID REFERENCES policies(id),
  PRIMARY KEY (role_id, policy_id)
);
```

**CEL Policy Example:**
```javascript
// Policy condition
"subject.department == 'engineering' &&
 resource.owner == subject.id ||
 subject.roles.contains('admin')"

// Evaluation context
{
  "subject": {
    "id": "user123",
    "department": "engineering",
    "roles": ["developer", "team-lead"]
  },
  "resource": {
    "owner": "user123",
    "project": "project456"
  }
}
```

### User Service

**Responsibility:** User CRUD, profile management

**API:**
```protobuf
service UserService {
  rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
  rpc GetUser(GetUserRequest) returns (GetUserResponse);
  rpc UpdateUser(UpdateUserRequest) returns (UpdateUserResponse);
  rpc DeleteUser(DeleteUserRequest) returns (DeleteUserResponse);
  rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
  rpc SearchUsers(SearchUsersRequest) returns (SearchUsersResponse);
}
```

**Database Schema:**
```sql
TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(100) UNIQUE NOT NULL,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  avatar_url TEXT,
  company_id UUID NOT NULL,
  department VARCHAR(100),
  location VARCHAR(100),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  INDEX idx_users_company (company_id),
  INDEX idx_users_email (email),
  INDEX idx_users_username (username)
);

TABLE user_preferences (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  language VARCHAR(10) DEFAULT 'en',
  timezone VARCHAR(50) DEFAULT 'UTC',
  theme VARCHAR(20) DEFAULT 'light',
  preferences JSONB DEFAULT '{}'::jsonb
);
```

**Events Published:**
- `user.created`
- `user.updated`
- `user.deleted`
- `user.activated`
- `user.deactivated`

### IAM Admin Service

**Responsibility:** Role and policy administration

**API:**
```protobuf
service IAMAdminService {
  // Roles
  rpc CreateRole(CreateRoleRequest) returns (CreateRoleResponse);
  rpc UpdateRole(UpdateRoleRequest) returns (UpdateRoleResponse);
  rpc DeleteRole(DeleteRoleRequest) returns (DeleteRoleResponse);
  rpc ListRoles(ListRolesRequest) returns (ListRolesResponse);

  // Policies
  rpc CreatePolicy(CreatePolicyRequest) returns (CreatePolicyResponse);
  rpc UpdatePolicy(UpdatePolicyRequest) returns (UpdatePolicyResponse);
  rpc DeletePolicy(DeletePolicyRequest) returns (DeletePolicyResponse);
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);

  // Assignments
  rpc AssignRoleToUser(AssignRoleRequest) returns (AssignRoleResponse);
  rpc RevokeRoleFromUser(RevokeRoleRequest) returns (RevokeRoleResponse);
  rpc AttachPolicyToRole(AttachPolicyRequest) returns (AttachPolicyResponse);
  rpc DetachPolicyFromRole(DetachPolicyRequest) returns (DetachPolicyResponse);
}
```

**Database Schema:**
```sql
TABLE user_roles (
  user_id UUID NOT NULL,
  role_id UUID NOT NULL,
  assigned_by UUID NOT NULL,
  assigned_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  PRIMARY KEY (user_id, role_id)
);
```

**Events Published:**
- `iam.role.created`
- `iam.role.updated`
- `iam.role.deleted`
- `iam.policy.created`
- `iam.policy.updated`
- `iam.policy.deleted`
- `iam.role.assigned`
- `iam.role.revoked`

### Task Service

**Responsibility:** Task and project management

**API:**
```protobuf
service TaskService {
  // Tasks
  rpc CreateTask(CreateTaskRequest) returns (CreateTaskResponse);
  rpc GetTask(GetTaskRequest) returns (GetTaskResponse);
  rpc UpdateTask(UpdateTaskRequest) returns (UpdateTaskResponse);
  rpc DeleteTask(DeleteTaskRequest) returns (DeleteTaskResponse);
  rpc ListTasks(ListTasksRequest) returns (ListTasksResponse);

  // Projects
  rpc CreateProject(CreateProjectRequest) returns (CreateProjectResponse);
  rpc GetProject(GetProjectRequest) returns (GetProjectResponse);
  rpc UpdateProject(UpdateProjectRequest) returns (UpdateProjectResponse);
  rpc DeleteProject(DeleteProjectRequest) returns (DeleteProjectResponse);

  // Assignments
  rpc AssignTask(AssignTaskRequest) returns (AssignTaskResponse);
  rpc UnassignTask(UnassignTaskRequest) returns (UnassignTaskResponse);
}
```

**Database Schema:**
```sql
TABLE projects (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  company_id UUID NOT NULL,
  owner_id UUID NOT NULL,
  status VARCHAR(50) DEFAULT 'active',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

TABLE tasks (
  id UUID PRIMARY KEY,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  project_id UUID REFERENCES projects(id),
  company_id UUID NOT NULL,
  assignee_id UUID,
  creator_id UUID NOT NULL,
  status VARCHAR(50) DEFAULT 'todo',
  priority VARCHAR(20) DEFAULT 'medium',
  due_date TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  INDEX idx_tasks_project (project_id),
  INDEX idx_tasks_assignee (assignee_id),
  INDEX idx_tasks_status (status)
);

TABLE task_comments (
  id UUID PRIMARY KEY,
  task_id UUID REFERENCES tasks(id),
  user_id UUID NOT NULL,
  comment TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

**Events Published:**
- `task.created`
- `task.updated`
- `task.deleted`
- `task.assigned`
- `task.completed`
- `task.commented`
- `project.created`
- `project.updated`
- `project.deleted`

### Audit Service

**Responsibility:** Event logging, compliance reporting

**API:**
```protobuf
service AuditService {
  rpc LogEvent(LogEventRequest) returns (LogEventResponse);
  rpc QueryEvents(QueryEventsRequest) returns (QueryEventsResponse);
  rpc GetComplianceReport(ComplianceReportRequest) returns (ComplianceReportResponse);
  rpc GetUserActivity(UserActivityRequest) returns (UserActivityResponse);
}
```

**Database Schema (TimescaleDB):**
```sql
CREATE TABLE audit_events (
  id UUID PRIMARY KEY,
  event_type VARCHAR(100) NOT NULL,
  actor_id UUID,
  actor_email VARCHAR(255),
  target_type VARCHAR(100),
  target_id UUID,
  company_id UUID NOT NULL,
  action VARCHAR(100) NOT NULL,
  result VARCHAR(50) NOT NULL, -- success, failure
  ip_address INET,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}'::jsonb,
  timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Convert to hypertable for time-series optimization
SELECT create_hypertable('audit_events', 'timestamp');

-- Automatic data retention (keep 90 days, then compress)
SELECT add_retention_policy('audit_events', INTERVAL '90 days');
SELECT add_compression_policy('audit_events', INTERVAL '7 days');

-- Indexes for common queries
CREATE INDEX idx_audit_company_time ON audit_events (company_id, timestamp DESC);
CREATE INDEX idx_audit_actor_time ON audit_events (actor_id, timestamp DESC);
CREATE INDEX idx_audit_type_time ON audit_events (event_type, timestamp DESC);
```

**Events Consumed:**
- All events from all exchanges (fanout)

### Notification Service

**Responsibility:** Email, webhooks, push notifications

**API:**
```protobuf
service NotificationService {
  rpc SendEmail(SendEmailRequest) returns (SendEmailResponse);
  rpc SendWebhook(SendWebhookRequest) returns (SendWebhookResponse);
  rpc SendPushNotification(SendPushRequest) returns (SendPushResponse);
  rpc GetNotificationHistory(GetHistoryRequest) returns (GetHistoryResponse);
}
```

**Database Schema:**
```sql
TABLE notification_templates (
  id UUID PRIMARY KEY,
  name VARCHAR(255) UNIQUE NOT NULL,
  type VARCHAR(50) NOT NULL, -- email, webhook, push
  subject VARCHAR(500),
  body TEXT NOT NULL,
  variables JSONB DEFAULT '[]'::jsonb,
  company_id UUID,
  created_at TIMESTAMP DEFAULT NOW()
);

TABLE notification_logs (
  id UUID PRIMARY KEY,
  type VARCHAR(50) NOT NULL,
  recipient VARCHAR(500) NOT NULL,
  subject VARCHAR(500),
  body TEXT,
  status VARCHAR(50) NOT NULL, -- pending, sent, failed
  error TEXT,
  sent_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  INDEX idx_notifications_status (status),
  INDEX idx_notifications_recipient (recipient)
);
```

**Events Consumed:**
- `user.created` → Send welcome email
- `user.password_reset` → Send reset link
- `task.assigned` → Notify assignee
- `task.completed` → Notify creator

## Data Architecture

### Multi-Tenancy Strategy

**Row-Level Isolation:**
```sql
-- Every table has company_id
CREATE TABLE <table_name> (
  ...
  company_id UUID NOT NULL,
  ...
);

-- Composite indexes for performance
CREATE INDEX idx_<table>_company_time
ON <table> (company_id, created_at DESC);
```

**Application-Level Enforcement:**
```go
// Middleware extracts company_id from JWT
func CompanyMiddleware(ctx context.Context, req interface{}) error {
    claims := jwt.FromContext(ctx)
    if claims.CompanyID == nil {
        return errors.PermissionDenied("no company context")
    }
    ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
    return nil
}

// Storage layer filters by company_id
func (s *Storage) GetUser(ctx context.Context, userID string) (*User, error) {
    companyID := ctx.Value("company_id").(string)
    var user User
    err := s.db.QueryRow(
        "SELECT * FROM users WHERE id = $1 AND company_id = $2",
        userID, companyID,
    ).Scan(&user)
    return &user, err
}
```

### Cache Strategy

**Per-Service Redis DB:**
```
Service                → Redis DB
──────────────────────────────────
authentication-service → DB 0
authorization-service  → DB 1
user-service          → DB 2
iam-admin-service     → DB 3
task-service          → DB 4
audit-service         → DB 5
notification-service  → DB 6
```

**Cache Key Namespace:**
```
{service}:{entity}:{id}:{field}

Examples:
- authz:permission:user123:tasks:edit:task456
- user:profile:user123
- task:details:task456
- auth:session:session-abc123
```

**TTL Strategy:**
```
Authorization decisions: 5 minutes
User profiles:          30 minutes
Task details:           10 minutes
Sessions:               7 days
```

**Invalidation:**
```go
// When policy changes
func (s *IAMAdminService) UpdatePolicy(ctx, req) (*UpdatePolicyResponse, error) {
    // Update database
    err := s.storage.UpdatePolicy(ctx, policy)

    // Invalidate related cache keys
    pattern := fmt.Sprintf("authz:permission:*")
    s.cache.DeletePattern(ctx, pattern)

    // Publish event
    s.queue.Publish("iam.events", "policy.updated", event)

    return &UpdatePolicyResponse{}, nil
}
```

## Communication Patterns

### Synchronous (gRPC)

**When to use:**
- Real-time requirements
- Request-response pattern
- Need immediate result

**Example:**
```
API Gateway → Authorization Service (check permission)
API Gateway → User Service (get user profile)
Task Service → User Service (validate assignee)
```

**Circuit Breaker:**
```go
breaker := gobreaker.NewCircuitBreaker(settings)

response, err := breaker.Execute(func() (interface{}, error) {
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    return client.GetUser(ctx, req)
})
```

### Asynchronous (RabbitMQ)

**When to use:**
- Fire-and-forget
- Multiple consumers
- Decoupling
- Eventual consistency

**Example:**
```
User Service → user.created event
  ├─ Audit Service (log event)
  ├─ Notification Service (welcome email)
  ├─ IAM Admin Service (assign default role)
  └─ Analytics Service (track signup)
```

**Reliability:**
```go
// Publisher confirms
err := channel.Confirm(false)
err = channel.Publish(
    exchange,
    routingKey,
    true,  // mandatory
    false, // immediate
    amqp.Publishing{
        ContentType:  "application/json",
        Body:         data,
        DeliveryMode: amqp.Persistent,
    },
)

// Consumer acknowledgment
for msg := range msgs {
    err := handler(msg)
    if err != nil {
        msg.Nack(false, false) // Send to DLQ
    } else {
        msg.Ack(false)
    }
}
```

## Security Architecture

### Authentication Flow

```
1. Client → API Gateway: POST /auth/login {email, password}
2. API Gateway → Authentication Service: gRPC Login()
3. Authentication Service:
   a. Query user from User Service
   b. Verify password (bcrypt)
   c. Generate JWT (access + refresh)
   d. Store session in Redis
   e. Publish auth.login.success event
4. API Gateway → Client: {access_token, refresh_token}
```

### Authorization Flow

```
1. Client → API Gateway: GET /tasks/123 (with JWT in header)
2. API Gateway:
   a. Verify JWT signature
   b. Extract user_id, company_id, roles
3. API Gateway → Authorization Service: Check(user:123, tasks:view, tasks/123)
4. Authorization Service:
   a. Check Redis cache (key: authz:user123:tasks:view:tasks/123)
   b. Cache miss → Query policies from database
   c. Evaluate CEL expression
   d. Cache result (TTL: 5 min)
   e. Return {allowed: true/false}
5. If allowed:
   API Gateway → Task Service: GetTask(123)
6. Task Service:
   a. Validate company_id matches
   b. Return task data
7. API Gateway → Client: task JSON
```

### JWT Structure

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user123",
    "email": "user@example.com",
    "company_id": "company456",
    "roles": ["developer", "team-lead"],
    "iat": 1234567890,
    "exp": 1234571490,
    "jti": "token-unique-id"
  },
  "signature": "..."
}
```

### Service-to-Service Security (Istio mTLS)

```yaml
# Istio PeerAuthentication
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: taskman
spec:
  mtls:
    mode: STRICT  # Require mTLS for all services
```

**Certificate Rotation:**
- Istio automatically rotates certificates
- Default: 24-hour certificate lifetime
- Zero-downtime rotation

### Secrets Management (Vault)

```
Vault Secrets:
├─ /secret/taskman/auth/jwt-access-secret
├─ /secret/taskman/auth/jwt-refresh-secret
├─ /secret/taskman/databases/auth-db-password
├─ /secret/taskman/databases/user-db-password
├─ /secret/taskman/redis/password
├─ /secret/taskman/rabbitmq/password
└─ /secret/taskman/smtp/password
```

**Dynamic Secrets:**
```bash
# PostgreSQL dynamic credentials
vault write database/roles/auth-service \
    db_name=auth-db \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Service requests credentials
vault read database/creds/auth-service
# Returns: {username: "v-root-auth-service-xyz", password: "abc123", ttl: 3600}
```

## Observability

### Metrics (Prometheus)

**RED Metrics:**
```
Rate:     taskman_requests_total{service, method, status}
Errors:   taskman_errors_total{service, method, error_type}
Duration: taskman_request_duration_seconds{service, method}
```

**USE Metrics:**
```
Utilization: taskman_cpu_usage_percent{service}
Saturation:  taskman_memory_usage_bytes{service}
Errors:      taskman_error_rate{service}
```

**Business Metrics:**
```
taskman_users_total{company}
taskman_tasks_created_total{company, status}
taskman_logins_total{company, success}
taskman_permission_checks_total{company, allowed}
```

### Logging (Structured JSON)

```json
{
  "timestamp": "2025-01-15T10:30:45Z",
  "level": "info",
  "service": "task-service",
  "trace_id": "abc123",
  "span_id": "def456",
  "request_id": "req-789",
  "user_id": "user123",
  "company_id": "company456",
  "message": "Task created successfully",
  "task_id": "task789",
  "duration_ms": 45
}
```

### Tracing (Jaeger)

```
Trace: Create Task Request
├─ Span: API Gateway (10ms)
│  ├─ Span: Verify JWT (2ms)
│  └─ Span: Check Permission (8ms)
│     ├─ Span: Redis GET (1ms) [cache miss]
│     └─ Span: PostgreSQL Query (7ms)
├─ Span: Task Service (35ms)
│  ├─ Span: Validate Request (5ms)
│  ├─ Span: PostgreSQL INSERT (25ms)
│  └─ Span: RabbitMQ Publish (5ms)
└─ Total: 45ms
```

### Alerting

```yaml
groups:
  - name: taskman_alerts
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: rate(taskman_errors_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "{{ $labels.service }} error rate is {{ $value }}"

      # High latency
      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(taskman_request_duration_seconds_bucket[5m])) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"
          description: "{{ $labels.service }} p99 latency is {{ $value }}s"

      # Service down
      - alert: ServiceDown
        expr: up{job=~"taskman-.*"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
          description: "{{ $labels.job }} has been down for 1 minute"
```

## Deployment Strategy

### Environments

```
Development:
├─ docker-compose.dev.yml (all services)
├─ Local PostgreSQL, Redis, RabbitMQ
└─ No Istio, simplified setup

Staging:
├─ Kubernetes (single cluster)
├─ Managed PostgreSQL (AWS RDS, GCP Cloud SQL)
├─ Managed Redis (ElastiCache, Memorystore)
├─ Managed RabbitMQ (CloudAMQP)
├─ Istio service mesh
└─ Full observability stack

Production:
├─ Kubernetes (multi-zone)
├─ PostgreSQL HA (Patroni or managed)
├─ Redis Cluster
├─ RabbitMQ Cluster (multi-AZ)
├─ Istio with mTLS
├─ Auto-scaling (HPA, VPA, Cluster Autoscaler)
└─ Multi-region (future)
```

### CI/CD Pipeline

```
GitHub Push
  ↓
GitHub Actions:
  ├─ Lint (golangci-lint)
  ├─ Test (go test -race -cover)
  ├─ Security Scan (gosec, trivy)
  ├─ Build Docker Image
  └─ Push to Registry (ECR, GCR, Docker Hub)
  ↓
ArgoCD (Staging):
  ├─ Detect new image
  ├─ Update Helm values
  ├─ Apply to staging namespace
  ├─ Run smoke tests
  └─ Slack notification
  ↓
Manual Approval (GitHub Environments)
  ↓
ArgoCD (Production):
  ├─ Canary deployment (10% traffic)
  ├─ Monitor metrics (5 min)
  ├─ Gradual rollout (25%, 50%, 100%)
  └─ Auto-rollback on errors
```

### Kubernetes Resources

```yaml
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authentication-service
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: authentication-service
        image: taskman-v2/authentication-service:v1.2.3
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 1Gi
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5

# HPA (Horizontal Pod Autoscaler)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: authentication-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: authentication-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Migration from v1

### Phase 1: Infrastructure Setup (Week 1-2)
```
✓ Provision 8 PostgreSQL databases
✓ Set up Redis (8 DBs)
✓ Configure RabbitMQ exchanges/queues
✓ Deploy Vault
✓ Configure Kong API Gateway
✓ Set up monitoring (Prometheus, Grafana, Jaeger)
```

### Phase 2: Service Development (Week 3-10)
```
✓ Shared libraries (logger, config, errors, etc.)
✓ Authentication Service (+ tests)
✓ User Service (+ tests)
✓ Authorization Service (+ CEL evaluator, tests)
✓ IAM Admin Service (+ tests)
✓ Task Service (+ tests)
✓ Audit Service (+ tests)
✓ Notification Service (+ tests)
✓ API Gateway configuration
```

### Phase 3: Data Migration (Week 11-12)
```
✓ Export data from v1
✓ Transform data to v2 schema
✓ Import to v2 databases
✓ Validate data integrity
✓ Set up dual-write (v1 + v2)
```

### Phase 4: Parallel Run (Week 13-16)
```
✓ Deploy v2 to production
✓ Route 5% traffic to v2
✓ Monitor metrics, errors, latency
✓ Gradually increase traffic (10%, 25%, 50%)
✓ Compare v1 vs v2 performance
```

### Phase 5: Cutover (Week 17-20)
```
✓ Route 100% traffic to v2
✓ Monitor for issues
✓ Keep v1 running as fallback (1 week)
✓ Decommission v1
✓ Celebrate! 🎉
```

## Design Decisions

### Why Go?
- **Performance**: Compiled, concurrent, low latency
- **Simplicity**: Easy to read, maintain, onboard
- **Ecosystem**: Rich gRPC, database, testing libraries
- **Deployment**: Single binary, small Docker images
- **Cloud Native**: Kubernetes, service mesh, observability

### Why gRPC over REST?
- **Performance**: Binary protocol, HTTP/2, multiplexing
- **Type Safety**: Protobuf schemas, code generation
- **Streaming**: Bidirectional streaming support
- **Ecosystem**: Load balancing, retries, deadlines built-in
- **Still Offer REST**: gRPC-Gateway for HTTP/JSON

### Why TimescaleDB for Audit?
- **Time-Series Optimized**: Audit logs are append-only, time-based
- **Automatic Compression**: Saves 90%+ storage
- **Data Retention**: Automatic expiration policies
- **Query Performance**: 10-100x faster for time-range queries
- **PostgreSQL Compatible**: No new query language to learn

### Why Istio over Linkerd?
- **Feature Complete**: Traffic management, security, observability
- **Industry Standard**: Used by Google, IBM, Red Hat
- **Ecosystem**: Large community, plugins, extensions
- **Production Proven**: Handles massive scale
- **Future Proof**: CNCF graduated project

### Why Kong over NGINX/Envoy?
- **API-First**: Designed for microservices
- **Plugin Ecosystem**: Rate limiting, auth, transformations
- **Admin API**: Programmatic configuration
- **Observability**: Built-in metrics, logging
- **Enterprise Support**: If needed in future

### Why Vault over AWS Secrets Manager?
- **Cloud Agnostic**: Works everywhere (AWS, GCP, Azure, on-prem)
- **Dynamic Secrets**: Auto-rotating database credentials
- **Encryption as a Service**: Encrypt/decrypt without managing keys
- **Audit Trail**: Who accessed which secret when
- **Open Source**: No vendor lock-in

## Conclusion

TaskMan v2 is a military-grade microservice architecture designed for:
- **Scalability**: Handle 10k+ RPS, scale services independently
- **Reliability**: 99.9% uptime, circuit breakers, auto-healing
- **Security**: mTLS, Vault, OAuth 2.0, RBAC/ABAC
- **Observability**: Metrics, logs, traces, alerts
- **Maintainability**: Clear boundaries, comprehensive tests
- **Extensibility**: Add services without affecting existing ones

**Next Steps:**
1. Run `make setup && make dev` to start development environment
2. Explore service APIs in `services/*/api/*.proto`
3. Read service-specific READMEs
4. Start building! 🚀