module github.com/taskman/v2/services/authentication-service

go 1.24.0

toolchain go1.24.2

require (
	github.com/lib/pq v1.10.9
	github.com/taskman/v2/services/audit-service v0.0.0-00010101000000-000000000000
	github.com/taskman/v2/services/iam-admin-service v0.0.0-00010101000000-000000000000
	github.com/taskman/v2/services/user-service v0.0.0-00010101000000-000000000000
	github.com/taskman/v2/shared v0.0.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.9
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/rabbitmq/amqp091-go v1.10.0 // indirect
	github.com/redis/go-redis/v9 v9.15.1 // indirect
	github.com/sony/gobreaker v1.0.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250929231259-57b25ae835d4 // indirect
)

replace github.com/taskman/v2/shared => ../../shared

replace github.com/taskman/v2/services/audit-service => ../audit-service

replace github.com/taskman/v2/services/iam-admin-service => ../iam-admin-service

replace github.com/taskman/v2/services/user-service => ../user-service
