BIN        := bin/skopos
MODULE     := github.com/julianhintermann-cmd/skopos
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE       ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build go-build test lint fmt clean

build: go-build

go-build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/skopos

test:
	go test ./...

lint:
	golangci-lint run

fmt:
	gofmt -w $$(git ls-files '*.go')

clean:
	rm -rf bin
