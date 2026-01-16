APP := core-engine
PKG := ./...
GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: all build run test lint proto migrate-up migrate-down

all: build

build:
	GOFLAGS=$(GOFLAGS) CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/core-engine

run:
	go run ./bin/$(APP)

test:
	go test $(PKG) -cover -race

lint:
	gofmt -s -w .
	go vet $(PKG)

proto:
	protoc -I proto \
	--go_out=pkg/proto/gen --go_opt=paths=source_relative \
	--go-grpc_out=pkg/proto/gen --go-grpc_opt=paths=source_relative \
	proto/*.proto

migrate-up:
	./scripts/migrate.sh up

migrate-down:
	./scripts/migrate.sh down