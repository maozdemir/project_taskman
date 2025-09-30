module github.com/taskman/v2/services/iam-admin-service

go 1.21

require (
    github.com/taskman/v2/shared v0.0.0
    google.golang.org/grpc v1.60.0
    google.golang.org/protobuf v1.32.0
    github.com/lib/pq v1.10.9
    github.com/redis/go-redis/v9 v9.4.0
    github.com/rabbitmq/amqp091-go v1.9.0
    github.com/sony/gobreaker v0.5.0
)

replace github.com/taskman/v2/shared => ../../shared
