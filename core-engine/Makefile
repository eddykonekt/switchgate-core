APP := switchgate
PKG := ./...
PROTO_DIR := proto
GEN_DIR := proto/gen

GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: all build run test lint proto migrate-up migrate-down

all: build

build:
	GOFLAGS=$(GOFLAGS) CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/switchgate

run:
	./bin/$(APP)

test:
	go test $(PKG) -cover -race

lint:
	gofmt -s -w .
	go vet $(PKG)

proto:
	protoc -I $(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/*.proto

migrate-up:
	go run ./cmd/migrate up

migrate-down:
	go run ./cmd/migrate down