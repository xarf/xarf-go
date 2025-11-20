.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: all
all: deps fmt lint test ## Run all checks and tests

.PHONY: deps
deps: ## Install dependencies
	go mod download
	go mod tidy

.PHONY: build
build: ## Build the library
	go build -v ./...

.PHONY: test
test: ## Run tests
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: test-coverage
test-coverage: test ## Run tests with coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: bench
bench: ## Run benchmarks
	go test -bench=. -benchmem ./...

.PHONY: fmt
fmt: ## Format code
	gofmt -s -w .
	go mod tidy

.PHONY: lint
lint: ## Run linter
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix: ## Run linter with auto-fix
	golangci-lint run --fix ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: clean
clean: ## Clean build artifacts
	rm -f coverage.out coverage.html
	go clean -testcache

.PHONY: install-tools
install-tools: ## Install development tools
	@echo "Installing golangci-lint..."
	@command -v golangci-lint >/dev/null 2>&1 || \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

.PHONY: check
check: fmt vet lint test ## Run all quality checks

.DEFAULT_GOAL := help
