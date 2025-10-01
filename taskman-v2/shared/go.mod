module github.com/taskman/v2/shared

go 1.22

toolchain go1.24.2

require (
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
	github.com/rabbitmq/amqp091-go v1.9.0
	github.com/redis/go-redis/v9 v9.4.0
	github.com/sony/gobreaker v0.5.0
	github.com/taskman/v2/services/iam-admin-service v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.27.0
	google.golang.org/grpc v1.68.1
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
)

replace github.com/taskman/v2/services/iam-admin-service => ../services/iam-admin-service

replace github.com/taskman/v2/services/user-service => ../services/user-service
