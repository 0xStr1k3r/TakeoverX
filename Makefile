# TakeoverX — development helpers.
#
# `make build` is all a user needs; everything else is for working on the tool.

BINARY  := takeoverx
PKG     := github.com/0xStr1k3r/TakeoverX
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# version lives in package cmd, so the -X path must be fully qualified.
LDFLAGS := -s -w -X $(PKG)/cmd.version=$(VERSION)

# Pure Go: no cgo, so the binary cross-compiles with nothing but the toolchain.
export CGO_ENABLED := 0

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the binary into ./takeoverx
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

.PHONY: install
install: ## Install into GOBIN
	go install -trimpath -ldflags "$(LDFLAGS)" .

.PHONY: test
test: ## Run the full test suite
	go test ./... -count=1

.PHONY: race
race: ## Run the test suite under the race detector
	go test ./... -count=1 -race

.PHONY: cover
cover: ## Run tests and report coverage
	go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

.PHONY: lint
lint: ## Vet and check formatting
	go vet ./...
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: shellcheck
shellcheck: ## Lint the installer
	shellcheck install.sh
	bash -n install.sh

.PHONY: check
check: lint shellcheck test ## Everything CI runs

.PHONY: clean
clean: ## Remove build artefacts
	rm -f $(BINARY) coverage.out report.html takeoverx.sarif

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'