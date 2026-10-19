.PHONY: build build-server build-client certs proto build-all test cover test-integration

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

build-all:
	@for p in $(PLATFORMS); do \
			os=$${p%/*}; arch=$${p#*/}; ext=""; \
			[ "$$os" = "windows" ] && ext=".exe"; \
			for cmd in server client; do \
					echo "building $$cmd $$os/$$arch"; \
					CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags="$(LDFLAGS)" \
							-o $(BIN_DIR)/$$cmd-$$os-$$arch$$ext ./cmd/$$cmd || exit 1; \
			done; \
	done

PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

proto:
	protoc -I $(PROTO_DIR) \
		--go_out=$(PROTO_DIR) --go_opt=paths=source_relative \
		--go_opt=default_api_level=API_OPAQUE \
		--go-grpc_out=$(PROTO_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)

certs:
	go run ./cmd/certgen -o $(CERTS_DIR)

test:
	go test ./...

cover:
	go test ./... -cover

test-integration:
	go test -tags integration ./...
