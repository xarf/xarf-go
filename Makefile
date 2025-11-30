.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: all
all: deps fmt lint test coverage ## Run all checks and tests

.PHONY: deps
deps: ## Install dependencies
	go mod download
	go mod tidy

.PHONY: build
build: ## Build the library
	go build -v ./...

.PHONY: test
test: ## Run tests
	go test -v -race ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out

.PHONY: coverage
coverage: ## Check coverage threshold (80%)
	@go test -coverprofile=coverage.out -covermode=atomic ./... > /dev/null 2>&1; \
	coverage=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Coverage: $$coverage%"; \
	if [ -z "$$coverage" ]; then \
		echo "ERROR: Could not determine coverage"; \
		exit 1; \
	fi; \
	if [ $$(echo "$$coverage < 80" | bc -l 2>/dev/null || echo 1) -eq 1 ]; then \
		echo "ERROR: Coverage $$coverage% below 80% threshold"; \
		exit 1; \
	fi

.PHONY: bench
bench: ## Run benchmarks
	go test -bench=. -benchmem ./...

.PHONY: fmt
fmt: ## Format code
	gofmt -s -w .
	go mod tidy

.PHONY: lint
lint: ## Run linter
	golangci-lint run --timeout=5m ./...

.PHONY: lint-fix
lint-fix: ## Run linter with auto-fix
	golangci-lint run --fix ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: security
security: ## Run security scanner
	@command -v gosec >/dev/null 2>&1 || { echo "gosec not installed. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; exit 1; }
	gosec -no-fail ./...

.PHONY: staticcheck
staticcheck: ## Run staticcheck
	@command -v staticcheck >/dev/null 2>&1 || { echo "staticcheck not installed. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1; }
	staticcheck ./...

.PHONY: clean
clean: ## Clean build artifacts
	rm -f coverage.out coverage.html
	go clean -cache -testcache

.PHONY: install-tools
install-tools: ## Install development tools
	@echo "Installing golangci-lint..."
	@command -v golangci-lint >/dev/null 2>&1 || \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin
	@echo "Installing gosec..."
	@command -v gosec >/dev/null 2>&1 || \
		go install github.com/securego/gosec/v2/cmd/gosec@latest
	@echo "Installing staticcheck..."
	@command -v staticcheck >/dev/null 2>&1 || \
		go install honnef.co/go/tools/cmd/staticcheck@latest
	@echo "Installing goimports..."
	@command -v goimports >/dev/null 2>&1 || \
		go install golang.org/x/tools/cmd/goimports@latest

.PHONY: check
check: fmt vet lint test ## Run all quality checks

.PHONY: quality
quality: lint security staticcheck coverage ## Run comprehensive quality checks
	@echo "All quality checks passed!"

.DEFAULT_GOAL := help
