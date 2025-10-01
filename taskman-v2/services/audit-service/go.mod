module github.com/taskman/v2/services/audit-service

go 1.21

require (
	github.com/google/uuid v1.5.0
	github.com/taskman/v2/shared v0.0.0
	google.golang.org/grpc v1.60.0
	google.golang.org/protobuf v1.32.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/rabbitmq/amqp091-go v1.9.0 // indirect
	github.com/sony/gobreaker v0.5.0 // indirect
	golang.org/x/net v0.16.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231002182017-d307bd883b97 // indirect
)

replace github.com/taskman/v2/shared => ../../shared
