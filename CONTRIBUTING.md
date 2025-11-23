# Contributing to XARF Go Parser

Thank you for your interest in contributing to the XARF Go parser! We welcome contributions from the community and appreciate your help in making this project better.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to contact@xarf.org.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with the following information:

- **Clear title and description** of the issue
- **Steps to reproduce** the problem
- **Expected behavior** vs. **actual behavior**
- **Code samples** or test cases that demonstrate the issue
- **Version** of the library you're using
- **Go version** and operating system

### Suggesting Features

We welcome feature requests! Please create an issue with:

- **Clear description** of the feature
- **Use case** explaining why this feature would be useful
- **Example code** showing how the feature might work
- **Compatibility considerations** with the XARF specification

### Pull Requests

We actively welcome pull requests! Here's how to contribute:

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for any new functionality
4. **Ensure all tests pass** and coverage remains >80%
5. **Update documentation** as needed
6. **Submit a pull request** with a clear description of changes

## Development Setup

### Prerequisites

- **Go**: Version 1.21 or higher
- **Git**: Latest stable version
- **make**: For using Makefile commands (optional but recommended)

### Getting Started

1. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/xarf-go.git
   cd xarf-go
   ```

2. **Install dependencies:**
   ```bash
   go mod download
   ```

3. **Build the project:**
   ```bash
   go build ./...
   ```

4. **Run tests:**
   ```bash
   go test ./...
   ```

### Development Commands

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Generate detailed coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run tests with race detector
go test -race ./...

# Format code
go fmt ./...

# Run linter (requires golangci-lint)
golangci-lint run

# Run static analysis
go vet ./...

# Build the module
go build ./...

# Tidy dependencies
go mod tidy
```

### Installing Development Tools

We recommend installing the following tools for development:

```bash
# golangci-lint for comprehensive linting
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# goimports for import formatting
go install golang.org/x/tools/cmd/goimports@latest

# staticcheck for static analysis
go install honnef.co/go/tools/cmd/staticcheck@latest
```

## Testing Requirements

All contributions must maintain or improve test coverage:

- **Minimum coverage**: 80% for all packages
- **Table-driven tests**: Preferred for testing multiple cases
- **Benchmark tests**: Required for performance-critical code
- **Example tests**: Encouraged for public APIs
- **Test file naming**: `*_test.go` in the same package

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Generate detailed coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Run specific test
go test -run TestParseName ./...

# Run tests with race detection
go test -race ./...
```

### Writing Tests

We follow Go testing best practices. Example test structure:

```go
package xarf_test

import (
    "testing"

    "github.com/xarf/xarf-go"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestParser_Parse(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    *xarf.Report
        wantErr bool
    }{
        {
            name: "valid report",
            input: `{"version":"4.0","reportType":"abuse"}`,
            want: &xarf.Report{
                Version:    "4.0",
                ReportType: "abuse",
            },
            wantErr: false,
        },
        {
            name:    "invalid JSON",
            input:   `{invalid}`,
            want:    nil,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            parser := xarf.NewParser()
            got, err := parser.Parse([]byte(tt.input))

            if tt.wantErr {
                require.Error(t, err)
                return
            }

            require.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

## Code Style Guidelines

### Go Standards

- **Go version**: 1.21 or higher
- **Go modules**: Required for dependency management
- **Code formatting**: Use `gofmt` or `goimports`
- **Effective Go**: Follow [Effective Go](https://golang.org/doc/effective_go) guidelines

### Naming Conventions

- **Packages**: Short, lowercase, single-word names (e.g., `xarf`, `parser`)
- **Exported identifiers**: PascalCase (e.g., `Parser`, `Report`, `ParseError`)
- **Unexported identifiers**: camelCase (e.g., `validateField`, `parseHeader`)
- **Constants**: CamelCase or PascalCase (e.g., `DefaultVersion`, `maxRetries`)
- **Interfaces**: Single-method interfaces often end with "-er" (e.g., `Parser`, `Validator`)

### Code Organization

```
xarf-go/
├── parser.go           # Core parser implementation
├── validator.go        # Validation logic
├── types.go           # Type definitions
├── errors.go          # Error types
├── parser_test.go     # Parser tests
├── validator_test.go  # Validator tests
├── examples_test.go   # Example tests
└── internal/          # Internal packages (not for external use)
```

### Error Handling

- **Return errors**: Don't panic in library code
- **Wrap errors**: Use `fmt.Errorf("context: %w", err)` for error wrapping
- **Custom errors**: Create specific error types for different failure modes
- **Error messages**: Start with lowercase, no punctuation at end

Example:

```go
// Custom error type
type ParseError struct {
    Field string
    Err   error
}

func (e *ParseError) Error() string {
    return fmt.Sprintf("parse error in field %q: %v", e.Field, e.Err)
}

func (e *ParseError) Unwrap() error {
    return e.Err
}

// Function with error handling
func Parse(data []byte) (*Report, error) {
    if len(data) == 0 {
        return nil, fmt.Errorf("empty input data")
    }

    var report Report
    if err := json.Unmarshal(data, &report); err != nil {
        return nil, &ParseError{
            Field: "json",
            Err:   err,
        }
    }

    return &report, nil
}
```

### Documentation

- **Package comments**: Every package needs a doc comment
- **Exported identifiers**: All exported functions, types, and constants need doc comments
- **Example tests**: Provide examples for public APIs
- **README updates**: Update documentation for new features

Example documentation:

```go
// Package xarf provides parsing and validation for XARF v4 reports.
//
// XARF (eXtended Abuse Reporting Format) is a standardized format for
// reporting various types of abuse including spam, phishing, and DDoS attacks.
//
// Basic usage:
//
//     parser := xarf.NewParser()
//     report, err := parser.Parse(jsonData)
//     if err != nil {
//         log.Fatal(err)
//     }
package xarf

// Parser handles parsing and validation of XARF reports.
type Parser struct {
    // Configuration options
}

// Parse converts JSON data into a validated XARF report.
//
// The input data must conform to the XARF v4 specification. If validation
// fails, a ParseError is returned with details about the failure.
//
// Example:
//
//     data := []byte(`{"version":"4.0","reportType":"abuse"}`)
//     report, err := parser.Parse(data)
//     if err != nil {
//         return err
//     }
func (p *Parser) Parse(data []byte) (*Report, error) {
    // Implementation
}
```

### Code Quality

We use several tools to maintain code quality:

```bash
# Format code
go fmt ./...
goimports -w .

# Vet code for common mistakes
go vet ./...

# Run comprehensive linting
golangci-lint run

# Static analysis
staticcheck ./...
```

### Performance

- **Avoid allocations** in hot paths
- **Use benchmarks** for performance-critical code
- **Profile when optimizing**: Don't guess, measure

Example benchmark:

```go
func BenchmarkParser_Parse(b *testing.B) {
    data := []byte(`{"version":"4.0","reportType":"abuse"}`)
    parser := xarf.NewParser()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := parser.Parse(data)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Commit Message Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring without feature changes
- `test`: Adding or updating tests
- `chore`: Maintenance tasks, dependency updates
- `perf`: Performance improvements

### Examples

```
feat(parser): add support for XARF v4.1 reports

Implement parsing logic for new fields introduced in v4.1 specification.
Maintains backward compatibility with v4.0 reports.

Closes #123
```

```
fix(validator): correct email validation

The previous validation was too permissive. Updated to follow RFC 5322
more strictly while maintaining compatibility with common email formats.

Fixes #456
```

## Pull Request Process

1. **Update documentation** for any changed functionality
2. **Add tests** covering your changes
3. **Ensure all tests pass**: `go test ./...`
4. **Verify coverage**: `go test -cover ./...`
5. **Format code**: `go fmt ./...`
6. **Run linters**: `golangci-lint run`
7. **Run vet**: `go vet ./...`
8. **Update CHANGELOG.md** if applicable
9. **Create pull request** with clear description

### Pull Request Template

Your PR description should include:

- **What**: Brief description of changes
- **Why**: Motivation and context
- **How**: Implementation approach
- **Testing**: How you tested the changes
- **Breaking changes**: Any breaking changes (if applicable)
- **Related issues**: Link to related issues

### Code Review

All pull requests require review before merging:

- At least **one approval** from a maintainer
- All **CI checks must pass**
- **No unresolved discussions**
- **Merge conflicts resolved**

## XARF Specification Compliance

All implementations must conform to the [XARF specification](https://xarf.org/spec/):

- Parse all **required fields**
- Validate **data types** correctly
- Support all **standard report types**
- Handle **optional fields** appropriately
- Implement proper **error handling**
- Maintain **backward compatibility** when possible

## Release Process

Releases are managed by maintainers:

1. Version tagged following [Semantic Versioning](https://semver.org/)
2. CHANGELOG.md updated with changes
3. Git tag created for the version
4. Module version published to pkg.go.dev

## Getting Help

- **Documentation**: Check the [README](README.md) and GoDoc
- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact the maintainers at contact@xarf.org

## License

By contributing to XARF Go Parser, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

Thank you for contributing to XARF! Your efforts help make abuse reporting more effective and standardized across the internet.
