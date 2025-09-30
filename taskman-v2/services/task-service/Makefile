.PHONY: proto build test run

proto:
	buf generate

build:
	go build -o bin/server ./cmd/server

test:
	go test -v -race -coverprofile=coverage.out ./...

test-coverage:
	go tool cover -html=coverage.out

run:
	go run cmd/server/main.go

lint:
	golangci-lint run ./...

docker-build:
	docker build -t taskman-v2/task-service:latest .

migrate-up:
	go run cmd/migrate/main.go up

migrate-down:
	go run cmd/migrate/main.go down
