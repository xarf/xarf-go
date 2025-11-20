# XARF Go Library

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/xarf/xarf-go?status.svg)](https://godoc.org/github.com/xarf/xarf-go)

A Go library for parsing, validating, and generating XARF v4 (eXtended Abuse Reporting Format) reports.

## Features

- **Parse** XARF v4 JSON reports with automatic type detection
- **Validate** reports against XARF v4 specification
- **Generate** compliant XARF reports programmatically
- **Support** for all 8 XARF categories:
  - Abuse
  - Messaging
  - Connection
  - Content
  - Copyright
  - Infrastructure
  - Vulnerability
  - Reputation
- **Type-safe** Go structs for all report types
- **On-behalf-of** reporting support
- **Comprehensive** test coverage
- **Zero dependencies** (except for testing)

## Installation

```bash
go get github.com/xarf/xarf-go
```

## Quick Start

### Parsing a XARF Report

```go
package main

import (
    "fmt"
    "log"

    "github.com/xarf/xarf-go"
)

func main() {
    jsonData := []byte(`{
        "xarf_version": "4.0.0",
        "report_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2024-01-15T10:30:00Z",
        "reporter": {
            "org": "Security Team",
            "contact": "abuse@example.com",
            "type": "automated"
        },
        "source_identifier": "192.0.2.100",
        "category": "connection",
        "type": "ddos",
        "evidence_source": "honeypot",
        "destination_ip": "203.0.113.10",
        "protocol": "tcp"
    }`)

    parser := xarf.NewParser(false)
    report, err := parser.Parse(jsonData)
    if err != nil {
        log.Fatal(err)
    }

    // Type assertion to access category-specific fields
    if connReport, ok := report.(*xarf.ConnectionReport); ok {
        fmt.Printf("DDoS attack from %s to %s\n",
            connReport.SourceIdentifier,
            connReport.DestinationIP)
    }
}
```

### Generating a XARF Report

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/xarf/xarf-go"
)

func main() {
    gen := xarf.NewGenerator()

    opts := xarf.ReportOptions{
        Category:         xarf.CategoryConnection,
        Type:             "ddos",
        SourceIdentifier: "192.0.2.100",
        ReporterContact:  "abuse@example.com",
        ReporterOrg:      "Example Security Team",
        Description:      "Sustained DDoS attack detected",
        Severity:         xarf.SeverityHigh,
    }

    report, err := gen.GenerateReport(opts)
    if err != nil {
        log.Fatal(err)
    }

    jsonData, _ := json.MarshalIndent(report, "", "  ")
    fmt.Println(string(jsonData))
}
```

### Validating a Report

```go
package main

import (
    "fmt"
    "log"

    "github.com/xarf/xarf-go"
)

func main() {
    parser := xarf.NewParser(false)
    report, err := parser.Parse(jsonData)
    if err != nil {
        log.Fatal(err)
    }

    validator := xarf.NewValidator()
    valid, errors := validator.ValidateReport(report)

    if !valid {
        fmt.Println("Validation errors:")
        for _, err := range errors {
            fmt.Printf("  - %s\n", err)
        }
    } else {
        fmt.Println("Report is valid!")
    }
}
```

### On-Behalf-Of Reporting

```go
package main

import (
    "github.com/xarf/xarf-go"
)

func main() {
    gen := xarf.NewGenerator()

    opts := xarf.ReportOptions{
        Category:         xarf.CategoryMessaging,
        Type:             "spam",
        SourceIdentifier: "192.0.2.100",
        ReporterContact:  "abuse@provider.com",
        ReporterOrg:      "Internet Service Provider",
        OnBehalfOf: &xarf.OnBehalfOf{
            Org:     "Customer Organization",
            Contact: "customer@example.com",
        },
    }

    report, err := gen.GenerateReport(opts)
    // ... handle report
}
```

## Supported Categories

### 1. Abuse
General abuse reports (DDoS, malware, phishing, spam, scanner)

### 2. Messaging
Email and messaging abuse (spam, phishing, social engineering, bulk messaging)

### 3. Connection
Network connection abuse (DDoS, port scans, login attacks, SQL injection, etc.)

### 4. Content
Web content abuse (phishing sites, malware distribution, defacement, web hacks)

### 5. Copyright
Copyright infringement (DMCA, trademark, P2P, cyberlocker, etc.)

### 6. Infrastructure
Infrastructure compromise (botnets, compromised servers)

### 7. Vulnerability
Security vulnerabilities (CVE, misconfigurations, open services)

### 8. Reputation
Reputation and threat intelligence (blocklists, threat feeds)

## Development

### Prerequisites

- Go 1.21 or higher
- golangci-lint for linting

### Building

```bash
make build
```

### Testing

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Run benchmarks
make bench
```

### Linting

```bash
# Run linter
make lint

# Run linter with auto-fix
make lint-fix
```

### Code Quality

```bash
# Run all quality checks
make check
```

## Project Structure

```
xarf-go/
├── types.go          # XARF type definitions and structs
├── parser.go         # Report parsing functionality
├── validator.go      # Report validation
├── generator.go      # Report generation
├── errors.go         # Error types
├── *_test.go         # Test files
├── .golangci.yml     # Linter configuration
├── Makefile          # Build automation
└── README.md         # This file
```

## API Documentation

Full API documentation is available at [pkg.go.dev](https://pkg.go.dev/github.com/xarf/xarf-go).

### Key Types

- `Report` - Base XARF report structure
- `MessagingReport` - Messaging category report
- `ConnectionReport` - Connection category report
- `ContentReport` - Content category report
- `AbusiveReport` - Abuse category report
- `VulnerabilityReport` - Vulnerability category report
- `CopyrightReport` - Copyright category report
- `InfrastructureReport` - Infrastructure category report
- `ReputationReport` - Reputation category report

### Key Functions

- `NewParser(strict bool)` - Create a new parser
- `NewValidator()` - Create a new validator
- `NewGenerator()` - Create a new generator

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`make test`)
2. Code is formatted (`make fmt`)
3. Linter passes (`make lint`)
4. Add tests for new features

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Related Projects

- [XARF Specification](https://github.com/xarf/xarf-spec)
- [XARF Python Library](https://github.com/xarf/xarf-python)

## Support

- GitHub Issues: [https://github.com/xarf/xarf-go/issues](https://github.com/xarf/xarf-go/issues)
- XARF Website: [https://xarf.org](https://xarf.org)

## XARF Version

This library implements **XARF v4.0.0** specification.
