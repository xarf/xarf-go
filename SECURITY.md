# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of xarf-go seriously. If you discover a security vulnerability, please follow these steps:

### 1. Do Not Open a Public Issue

Please **do not** open a GitHub issue for security vulnerabilities, as this could put users at risk.

### 2. Report Privately

Send security vulnerability reports to:

**Email**: security@xarf.org

Please include:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (if applicable)
- Your contact information for follow-up

### 3. Response Timeline

- **Initial Response**: Within 48 hours of receiving your report
- **Status Update**: Within 7 days with preliminary assessment
- **Fix Timeline**: Critical vulnerabilities will be addressed within 30 days

### 4. Coordinated Disclosure

We follow a coordinated disclosure process:

1. We will acknowledge receipt of your report
2. We will investigate and validate the vulnerability
3. We will develop and test a fix
4. We will release a security update
5. We will publicly disclose the vulnerability after the fix is released

We kindly ask that you:
- Allow us reasonable time to address the issue before public disclosure
- Make a good faith effort to avoid privacy violations and data destruction
- Do not exploit the vulnerability beyond what is necessary to demonstrate it

### 5. Recognition

We maintain a security acknowledgments page to recognize researchers who responsibly disclose vulnerabilities. If you would like to be acknowledged, please let us know in your report.

## Security Best Practices

When using xarf-go in your applications:

### Input Validation

Always validate XARF reports before processing:

```go
parser := xarf.NewParser(true) // Use strict mode
report, err := parser.Parse(data)
if err != nil {
    // Handle invalid reports
    return err
}

validator := xarf.NewValidator()
valid, errors := validator.ValidateReport(report)
if !valid {
    // Handle validation errors
    return fmt.Errorf("invalid report: %v", errors)
}
```

### Rate Limiting

Implement rate limiting when accepting XARF reports from external sources to prevent abuse:

```go
// Example using a rate limiter
limiter := rate.NewLimiter(rate.Limit(100), 10) // 100 requests per second, burst of 10

func handleReport(data []byte) error {
    if !limiter.Allow() {
        return errors.New("rate limit exceeded")
    }

    // Process report
    parser := xarf.NewParser(true)
    report, err := parser.Parse(data)
    // ...
}
```

### Size Limits

Set reasonable size limits for incoming reports to prevent memory exhaustion:

```go
const maxReportSize = 10 * 1024 * 1024 // 10MB

func validateReportSize(data []byte) error {
    if len(data) > maxReportSize {
        return errors.New("report exceeds maximum size")
    }
    return nil
}
```

### Evidence Handling

Be cautious when handling evidence payloads, especially when they contain executable content:

```go
func processEvidence(evidence *xarf.Evidence) error {
    // Validate content type
    allowedTypes := map[string]bool{
        "text/plain":       true,
        "application/json": true,
        "image/png":        true,
        // Add other safe types
    }

    if !allowedTypes[evidence.ContentType] {
        return errors.New("unsupported content type")
    }

    // Verify hash
    computed := sha256.Sum256([]byte(evidence.Payload))
    computedHash := hex.EncodeToString(computed[:])

    if computedHash != evidence.Hash {
        return errors.New("evidence hash mismatch")
    }

    // Process evidence safely
    return nil
}
```

### Sanitize Outputs

When displaying or logging XARF report data, sanitize outputs to prevent injection attacks:

```go
import "html/template"

func displayReport(report *xarf.Report) string {
    // Use HTML escaping for web display
    return template.HTMLEscapeString(report.Description)
}
```

### Dependency Security

Keep dependencies up to date:

```bash
# Check for security vulnerabilities in dependencies
go list -json -m all | nancy sleuth

# Update dependencies
go get -u ./...
go mod tidy
```

## Known Security Considerations

### 1. JSON Parsing

The library uses Go's standard `encoding/json` package, which is generally safe but:
- Very large JSON documents could cause high memory usage
- Deeply nested structures could cause stack overflow
- Always set size limits on incoming data

### 2. Regular Expressions

Validation uses regex for email and domain validation:
- These patterns are designed to prevent ReDoS (Regular Expression Denial of Service)
- If you modify validation patterns, ensure they are not vulnerable to ReDoS

### 3. Evidence Payloads

Evidence payloads can contain arbitrary data:
- Always validate content types before processing
- Verify hashes to ensure data integrity
- Never execute or render untrusted evidence without sandboxing

### 4. V3 Compatibility

When processing v3 reports:
- The conversion process creates new report IDs
- Additional validation is recommended for converted reports
- Timestamp parsing uses multiple fallback formats - ensure this fits your security requirements

## Cryptographic Functions

The library provides:
- SHA-256 hashing (default)
- SHA-512 hashing
- UUID v4 generation using crypto/rand

These use Go's standard `crypto` package, which is FIPS 140-2 compliant when built appropriately.

## Compliance

This library is designed to help with abuse reporting workflows and may process:
- IP addresses
- Email addresses
- Domain names
- Potentially sensitive evidence

Ensure your use of this library complies with:
- GDPR (if processing EU data)
- CCPA (if processing California resident data)
- Other relevant privacy regulations in your jurisdiction

## Updates and Notifications

- Security updates are released as patch versions (e.g., 1.0.1)
- Critical security fixes may be backported to older supported versions
- Subscribe to GitHub releases to be notified of security updates

## Contact

For security-related questions or concerns:

- **Security Issues**: security@xarf.org
- **General Issues**: [GitHub Issues](https://github.com/xarf/xarf-go/issues)
- **Discussions**: [GitHub Discussions](https://github.com/xarf/xarf-go/discussions)

---

Last Updated: 2025-11-30
