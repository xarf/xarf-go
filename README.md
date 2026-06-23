# XARF Go Library

![XARF Spec](https://img.shields.io/badge/XARF%20Spec-v4.2.0-blue)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/xarf/xarf-go?status.svg)](https://godoc.org/github.com/xarf/xarf-go)

A Go library for parsing, validating, and generating XARF v4 (eXtended Abuse Reporting Format) reports.

**Library Version:** v1.0.0
**XARF Specification:** v4.2.0

## Features

- **Parse** XARF v4 JSON reports with automatic type detection
- **Validate** reports against XARF v4 specification
- **Generate** compliant XARF reports programmatically
- **Strict Compliance** - Requires "category" field as per XARF v4.2.0 specification
- **Support** for all 7 XARF categories:
  - Messaging
  - Connection
  - Content
  - Copyright
  - Infrastructure
  - Vulnerability
  - Reputation
- **Type-safe** Go structs for all report types
- **Third-party reporting** support (separate reporter/sender fields)
- **Comprehensive** test coverage
- **Zero dependencies** (except for testing)

## Installation

```bash
go get github.com/xarf/xarf-go
```

## JavaScript-parity API

The package-level `Parse`, `CreateReport`, and `CreateEvidence` functions mirror
the official JavaScript library ([`@xarf/xarf`](https://www.npmjs.com/package/@xarf/xarf)):
the same schema-driven validation (against the embedded v4.2.0 schemas), v3
auto-detection and conversion, strict mode that promotes `x-recommended` fields
to required, and identical evidence encoding.

```go
import "github.com/xarf/xarf-go"

// Parse returns a result with errors/warnings rather than failing; an error is
// returned only for malformed JSON or input exceeding MaxInputBytes. v3 reports
// are auto-detected and converted (with a deprecation warning in Warnings).
result, err := xarf.Parse(data, &xarf.ParseOptions{ShowMissingOptional: true})
if err != nil { /* malformed JSON */ }
if len(result.Errors) == 0 {
    // result.Report is the validated report object (map[string]interface{})
}
// result.Warnings   — unknown fields, v3 deprecation
// result.Info        — missing optional/recommended fields (ShowMissingOptional)

// CreateReport auto-fills xarf_version, report_id (UUID), and timestamp.
created := xarf.CreateReport(map[string]any{
    "category": "messaging", "type": "spam",
    "source_identifier": "192.0.2.100", "source_port": 25,
    "protocol": "smtp", "smtp_from": "spammer@example.com",
    "evidence_source": "spamtrap",
    "reporter": map[string]any{"org": "Acme", "contact": "abuse@acme.example", "domain": "acme.example"},
    "sender":   map[string]any{"org": "Acme", "contact": "abuse@acme.example", "domain": "acme.example"},
}, nil)

// CreateEvidence base64-encodes the payload and prefixes the hash with the algorithm.
ev := xarf.CreateEvidence("message/rfc822", rawEmail, &xarf.EvidenceOptions{
    Description: "Original spam email", HashAlgorithm: "sha256",
})
// ev.Payload (base64), ev.Hash ("sha256:<hex>"), ev.Size
```

`ParseOptions.Strict` reports warnings and `x-recommended` fields as errors.
Version constants: `xarf.SpecVersion` (`"4.2.0"`), `xarf.BundledSpecVersion`
(`"v4.2.0"`), `xarf.Version` (library version).

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
        "xarf_version": "4.2.0",
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

## XARF v3 Backwards Compatibility

This library automatically handles legacy XARF v3 reports with transparent conversion to v4 format.

### Automatic Detection and Conversion

```go
package main

import (
    "fmt"
    "log"
    "github.com/xarf/xarf-go"
)

func main() {
    // V3 format report
    v3Data := []byte(`{
        "Version": "3.0.0",
        "ReporterInfo": {
            "ReporterOrg": "Security Team",
            "ReporterOrgEmail": "abuse@example.com"
        },
        "Report": {
            "ReportClass": "Messaging",
            "ReportType": "spam",
            "SourceIP": "192.0.2.100"
        }
    }`)

    // Parser automatically detects and converts v3
    parser := xarf.NewParser(false)
    report, err := parser.Parse(v3Data)
    if err != nil {
        log.Fatal(err)
    }

    // Now in v4 format
    fmt.Printf("Category: %s\n", report.GetCategory())
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

### Third-Party Reporting (Reporter vs Sender)

XARF v4 supports third-party reporting through separate `reporter` and `sender` fields:

- **reporter**: The original entity that detected/reported the abuse
- **sender**: The entity transmitting the report (may be different)

#### Direct Reporting (Reporter = Sender)

When you're reporting abuse you directly detected:

```go
package main

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/xarf/xarf-go"
)

func main() {
    // Direct reporting: you are both reporter and sender
    contactInfo := xarf.ContactInfo{
        Org:     "Example Security Team",
        Contact: "abuse@example.com",
        Domain:  "example.com",
    }

    report := xarf.MessagingReport{
        Report: xarf.Report{
            XARFVersion:      "4.2.0",
            ReportID:         "550e8400-e29b-41d4-a716-446655440000",
            Timestamp:        time.Now(),
            Reporter:         contactInfo, // You detected it
            Sender:           contactInfo, // You're sending it
            SourceIdentifier: "192.0.2.100",
            Category:         xarf.CategoryMessaging,
            Type:             "spam",
            EvidenceSource:   xarf.EvidenceSourceSpamtrap,
        },
        Protocol: "smtp",
    }

    jsonData, _ := json.MarshalIndent(report, "", "  ")
    fmt.Println(string(jsonData))
}
```

#### Third-Party Reporting (Reporter ≠ Sender)

When forwarding abuse reports on behalf of others (e.g., ISP forwarding customer reports):

```go
package main

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/xarf/xarf-go"
)

func main() {
    // Original reporter (your customer)
    reporter := xarf.ContactInfo{
        Org:     "Customer Organization",
        Contact: "security@customer.com",
        Domain:  "customer.com",
    }

    // Sender (you, forwarding on their behalf)
    sender := xarf.ContactInfo{
        Org:     "Internet Service Provider",
        Contact: "abuse@isp.com",
        Domain:  "isp.com",
    }

    report := xarf.MessagingReport{
        Report: xarf.Report{
            XARFVersion:      "4.2.0",
            ReportID:         "550e8400-e29b-41d4-a716-446655440001",
            Timestamp:        time.Now(),
            Reporter:         reporter, // Customer who detected abuse
            Sender:           sender,   // ISP forwarding the report
            SourceIdentifier: "192.0.2.100",
            Category:         xarf.CategoryMessaging,
            Type:             "spam",
            EvidenceSource:   xarf.EvidenceSourceUserReport,
        },
        Protocol: "smtp",
    }

    jsonData, _ := json.MarshalIndent(report, "", "  ")
    fmt.Println(string(jsonData))
}
```

## Supported Categories

### 1. Messaging
Email and messaging abuse (spam, phishing, social engineering, bulk messaging)

### 2. Connection
Network connection abuse (DDoS, port scans, login attacks, SQL injection, etc.)

### 3. Content
Web content abuse (phishing sites, malware distribution, defacement, web hacks)

### 4. Copyright
Copyright infringement (DMCA, trademark, P2P, cyberlocker, etc.)

### 5. Infrastructure
Infrastructure compromise (botnets, compromised servers)

### 6. Vulnerability
Security vulnerabilities (CVE, misconfigurations, open services)

### 7. Reputation
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

## Specification Compliance

This library strictly implements the XARF v4.2.0 specification, requiring the "category" field for all reports. Reports using the deprecated "class" field will fail validation.

**Important:**
- ✅ Only "category" field is accepted (XARF v4 spec requirement)
- ✅ Always outputs "category" when generating
- ❌ "class" field is not supported (breaking change from earlier alpha versions)

## Related Projects

- [XARF Specification](https://github.com/xarf/xarf-spec)
- [XARF Python Library](https://github.com/xarf/xarf-python)

## Support

- GitHub Issues: [https://github.com/xarf/xarf-go/issues](https://github.com/xarf/xarf-go/issues)
- XARF Website: [https://xarf.org](https://xarf.org)

## Version Information

- **Library Version:** v1.0.0
- **XARF Specification:** v4.2.0

This library implements the **XARF v4.2.0** specification. The library uses independent versioning starting from v1.0.0, which allows the library version to evolve independently of the XARF specification version.
