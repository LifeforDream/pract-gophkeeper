.PHONY: build build-server build-client certs proto test cover test-integration

DATE := $(shell date +%Y-%m-%dT%H:%M:%S)

VERSION := $(shell cat VERSION)

CERTS_DIR := certs
BIN_DIR := bin
PROTO_DIR := api

LDFLAGS := -X main.buildVersion=$(VERSION) -X main.buildDate=$(DATE)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

build-client:
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/client ./cmd/client

build-server:
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/server ./cmd/server

build: build-server build-client

PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

proto:
	protoc -I $(PROTO_DIR) \
		--go_out=$(PROTO_DIR) --go_opt=paths=source_relative \
		--go_opt=default_api_level=API_OPAQUE \
		--go-grpc_out=$(PROTO_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)

certs:
	rm -f $(addprefix $(CERTS_DIR)/,ca.pem ca.key server.pem server.key)
	go run ./cmd/certgen -o $(CERTS_DIR)

test:
	go test ./...

cover:
	go test ./... -cover

test-integration:
	go test -tags integration ./... -race
