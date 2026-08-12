BIN        := bin/skopos
MODULE     := github.com/julianhintermann-cmd/skopos
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE       ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build go-build web-build web-dev run-demo test test-integration lint fmt generate clean

build: web-build
	CGO_ENABLED=0 go build -trimpath -tags embedui -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/skopos

go-build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/skopos

web-build:
	cd web && npm install --no-audit --no-fund && npm run build

web-dev:
	cd web && npm install --no-audit --no-fund && npm run dev

run-demo: build
	./$(BIN) serve --demo

test:
	go test ./...
	cd web && npm run typecheck

test-integration:
	sudo -E go test -tags=integration -run Integration ./internal/firewall/...

lint:
	golangci-lint run
	cd web && npm run typecheck

fmt:
	gofmt -w $$(git ls-files '*.go')

generate:
	go generate ./...

clean:
	rm -rf bin web/dist
