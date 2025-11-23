# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 4.0.0-alpha.1 | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in this project, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email security details to: **security@xarf.org**

Include the following information in your report:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if available)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Assessment**: We will assess the severity and impact of the vulnerability
- **Updates**: We will keep you informed of our progress toward a fix
- **Disclosure**: Once a fix is available, we will coordinate disclosure timing with you

## Security Best Practices

When using the XARF Go parser, follow these security best practices:

### Input Validation

1. **Always validate XARF reports** against the schema before processing
2. **Sanitize all user-supplied data** before using it in XARF reports
3. **Set size limits** on incoming reports to prevent memory exhaustion
4. **Validate email addresses** and other contact information before use

### Safe Parsing

```go
// Example: Safe parsing with error handling
func processXARF(input []byte) error {
    // Set maximum input size
    const maxSize = 10 * 1024 * 1024 // 10MB
    if len(input) > maxSize {
        return errors.New("input exceeds maximum size")
    }

    // Parse with error handling
    report, err := parser.Parse(input)
    if err != nil {
        log.Printf("Parsing failed: %v", err)
        return fmt.Errorf("invalid XARF report: %w", err)
    }

    // Validate against schema
    if err := validator.Validate(report); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    // Process validated report
    return processReport(report)
}
```

### Data Handling

1. **Do not log sensitive information** from XARF reports
2. **Redact PII** when logging or storing reports
3. **Use secure transport** (HTTPS/TLS) when transmitting reports
4. **Encrypt sensitive data** at rest

### Dependency Management

1. **Regularly update dependencies** to patch known vulnerabilities
2. **Use `go mod tidy`** and `go mod verify` regularly
3. **Review security advisories** for dependencies
4. **Use `govulncheck`** to scan for known vulnerabilities

```bash
# Install and run govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

### Code Practices

1. **Use bounded buffers** when reading input
2. **Validate all inputs** before processing
3. **Avoid unsafe package** unless absolutely necessary
4. **Use context with timeouts** for long-running operations
5. **Follow principle of least privilege** in code design

### Concurrency Safety

1. **Protect shared state** with appropriate synchronization
2. **Avoid race conditions** (use `go test -race`)
3. **Handle goroutine lifecycle** properly
4. **Use channels safely** to prevent deadlocks

## Known Security Considerations

### XARF Report Content

XARF reports may contain:
- Email addresses and contact information
- IP addresses and network data
- Potentially malicious content samples
- Sensitive abuse details

**Always treat XARF report content as untrusted user input.**

### Schema Validation

While the parser validates structure, additional application-level validation may be required for:
- Email address format verification
- IP address range validation
- URL safety checks
- Content length restrictions

### Memory Safety

Go provides memory safety, but consider:
- **Denial of Service**: Limit input sizes to prevent memory exhaustion
- **Resource limits**: Set timeouts and resource constraints
- **Goroutine leaks**: Ensure proper cleanup of concurrent operations

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed and fixed. Updates will be announced through:
- GitHub Security Advisories
- Release notes
- Project changelog

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged (with their permission) in our security advisories.
