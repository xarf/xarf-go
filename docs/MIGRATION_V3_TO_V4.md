# XARF v3 to v4 Migration Guide

This guide helps you migrate from XARF v3 format to XARF v4 format, both for data migration and for updating applications that generate or consume XARF reports.

## Table of Contents

1. [Overview](#overview)
2. [Key Differences](#key-differences)
3. [Automatic Conversion](#automatic-conversion)
4. [Field Mapping](#field-mapping)
5. [Category Changes](#category-changes)
6. [Code Migration](#code-migration)
7. [Testing](#testing)
8. [Common Issues](#common-issues)

## Overview

XARF v4 introduces several improvements over v3:

- **Simplified field names**: More consistent naming convention
- **Enhanced third-party reporting**: Separate `reporter` and `sender` fields
- **Standardized categories**: Refined category definitions
- **Better evidence handling**: Improved evidence source enumeration
- **Modern JSON structure**: More developer-friendly field names

## Key Differences

### Version Field

```json
// v3
{
  "Version": "3.0.0"
}

// v4
{
  "xarf_version": "4.0.0"
}
```

### Reporter Information

```json
// v3
{
  "ReporterInfo": {
    "ReporterOrg": "Security Team",
    "ReporterOrgDomain": "example.com",
    "ReporterOrgEmail": "abuse@example.com"
  }
}

// v4
{
  "reporter": {
    "org": "Security Team",
    "domain": "example.com",
    "contact": "abuse@example.com"
  },
  "sender": {
    "org": "Security Team",
    "domain": "example.com",
    "contact": "abuse@example.com"
  }
}
```

### Report Data

```json
// v3
{
  "Report": {
    "ReportClass": "Messaging",
    "ReportType": "spam",
    "SourceIP": "192.0.2.100",
    "Date": "2024-01-15T10:30:00Z"
  }
}

// v4
{
  "category": "messaging",
  "type": "spam",
  "source_identifier": "192.0.2.100",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Automatic Conversion

The xarf-go library provides automatic conversion from v3 to v4 format:

### Using the Parser

```go
package main

import (
    "fmt"
    "log"
    "github.com/xarf/xarf-go"
)

func main() {
    // Your v3 report data
    v3Data := []byte(`{
        "Version": "3.0.0",
        "ReporterInfo": {
            "ReporterOrg": "Security Team",
            "ReporterOrgDomain": "example.com",
            "ReporterOrgEmail": "abuse@example.com"
        },
        "Report": {
            "ReportClass": "Connection",
            "ReportType": "ddos",
            "SourceIP": "192.0.2.100",
            "Date": "2024-01-15T10:30:00Z",
            "DestinationIP": "203.0.113.10",
            "Protocol": "tcp"
        }
    }`)

    // Parser automatically detects and converts v3
    parser := xarf.NewParser(false)
    report, err := parser.Parse(v3Data)
    if err != nil {
        log.Fatal(err)
    }

    // Report is now in v4 format
    if connReport, ok := report.(*xarf.ConnectionReport); ok {
        fmt.Printf("Category: %s\n", connReport.Category)
        fmt.Printf("Type: %s\n", connReport.Type)
        fmt.Printf("Destination IP: %s\n", connReport.DestinationIP)
    }
}
```

### Manual Conversion

For more control over the conversion process:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "github.com/xarf/xarf-go"
)

func main() {
    v3Data := []byte(`{ ... }`) // Your v3 report

    // Check if it's a v3 report
    if xarf.IsV3Report(v3Data) {
        // Convert to v4 format
        v4Data, err := xarf.ConvertV3ToV4(v3Data)
        if err != nil {
            log.Fatal(err)
        }

        // Now parse as v4
        parser := xarf.NewParser(false)
        report, err := parser.Parse(v4Data)
        if err != nil {
            log.Fatal(err)
        }

        // Use the v4 report
        fmt.Printf("Report ID: %s\n", report.(*xarf.Report).ReportID)
    }
}
```

## Field Mapping

### Core Fields

| v3 Field | v4 Field | Notes |
|----------|----------|-------|
| `Version` | `xarf_version` | Changed to lowercase with underscore |
| `ReporterInfo.ReporterOrg` | `reporter.org` | Nested structure flattened |
| `ReporterInfo.ReporterOrgEmail` | `reporter.contact` | Renamed for clarity |
| `ReporterInfo.ReporterOrgDomain` | `reporter.domain` | Simplified name |
| `Report.ReportClass` | `category` | Lowercase, extracted to top level |
| `Report.ReportType` | `type` | Extracted to top level |
| `Report.SourceIP` | `source_identifier` | More generic identifier |
| `Report.Date` | `timestamp` | Renamed for clarity |
| - | `sender` | **New in v4**: Separate from reporter |
| - | `report_id` | **New in v4**: UUID for each report |

### Category-Specific Fields

#### Messaging (Email)

| v3 Field | v4 Field |
|----------|----------|
| `SMTPFrom` | `smtp_from` |
| `SMTPTo` | `smtp_to` |
| `Subject` | `subject` |
| `MessageID` | `message_id` |

#### Connection

| v3 Field | v4 Field |
|----------|----------|
| `DestinationIP` | `destination_ip` |
| `DestinationPort` | `destination_port` |
| `Protocol` | `protocol` |

#### Content

| v3 Field | v4 Field |
|----------|----------|
| `URL` | `url` |
| `ContentType` | `content_type` |

## Category Changes

### The "Abuse" Category

**Important**: XARF v3 had an "Abuse" category that does not exist in XARF v4.

The v4 specification defines exactly 7 categories:
1. `messaging`
2. `connection`
3. `content`
4. `copyright`
5. `infrastructure`
6. `vulnerability`
7. `reputation`

**Migration Path**: Reports using the v3 "Abuse" category should be mapped to the appropriate v4 category:

```go
// Automatic mapping in xarf-go
var V3CategoryMapping = map[string]string{
    "Abuse":          "connection",  // Default mapping
    "Messaging":      "messaging",
    "Connection":     "connection",
    "Content":        "content",
    "Copyright":      "copyright",
    "Infrastructure": "infrastructure",
    "Vulnerability":  "vulnerability",
    "Reputation":     "reputation",
}
```

#### Manual Category Selection

If you're converting v3 reports, choose the most appropriate v4 category:

- **DDoS, network attacks** → `connection`
- **Malware, phishing emails** → `messaging` (if email-related) or `content` (if web-based)
- **Port scans, brute force** → `connection`
- **Compromised servers** → `infrastructure`
- **Security vulnerabilities** → `vulnerability`

### Case Sensitivity

All v4 categories are **lowercase**:

```go
// v3 (mixed case)
"ReportClass": "Messaging"

// v4 (lowercase)
"category": "messaging"
```

## Code Migration

### Updating Report Generation

#### v3 Style (Before)

```go
// v3 structure (pseudo-code, not actual xarf-go v3)
report := map[string]interface{}{
    "Version": "3.0.0",
    "ReporterInfo": map[string]interface{}{
        "ReporterOrg": "Security Team",
        "ReporterOrgEmail": "abuse@example.com",
        "ReporterOrgDomain": "example.com",
    },
    "Report": map[string]interface{}{
        "ReportClass": "Messaging",
        "ReportType": "spam",
        "SourceIP": "192.0.2.100",
    },
}
```

#### v4 Style (After)

```go
// v4 using xarf-go generator
gen := xarf.NewGenerator()

reporter := xarf.ContactInfo{
    Org:     "Security Team",
    Contact: "abuse@example.com",
    Domain:  "example.com",
}

opts := &xarf.ReportOptions{
    Category:         xarf.CategoryMessaging,
    Type:             "spam",
    SourceIdentifier: "192.0.2.100",
    Reporter:         reporter,
    Sender:           reporter, // Same as reporter for direct reporting
    EvidenceSource:   xarf.EvidenceSourceSpamtrap,
}

report, err := gen.GenerateReport(opts)
if err != nil {
    log.Fatal(err)
}
```

### Updating Report Parsing

#### v3 Parsing (Before)

```go
// Custom v3 parsing logic
var v3Report map[string]interface{}
json.Unmarshal(data, &v3Report)

reportClass := v3Report["Report"].(map[string]interface{})["ReportClass"].(string)
```

#### v4 Parsing (After)

```go
// Automatic v3/v4 detection and parsing
parser := xarf.NewParser(false)
report, err := parser.Parse(data) // Handles both v3 and v4

// Type-safe access
if msgReport, ok := report.(*xarf.MessagingReport); ok {
    category := msgReport.Category
    reportType := msgReport.Type
}
```

## Testing

### Test Both Formats

When migrating, ensure your application handles both v3 and v4 reports:

```go
func TestReportParsing(t *testing.T) {
    parser := xarf.NewParser(false)

    // Test v3 report
    v3Data := []byte(`{"Version": "3.0.0", ...}`)
    v3Report, err := parser.Parse(v3Data)
    assert.NoError(t, err)
    assert.NotNil(t, v3Report)

    // Test v4 report
    v4Data := []byte(`{"xarf_version": "4.0.0", ...}`)
    v4Report, err := parser.Parse(v4Data)
    assert.NoError(t, err)
    assert.NotNil(t, v4Report)
}
```

### Validate Converted Reports

```go
func TestV3Conversion(t *testing.T) {
    v3Data := []byte(`{...}`)

    // Convert v3 to v4
    v4Data, err := xarf.ConvertV3ToV4(v3Data)
    assert.NoError(t, err)

    // Parse and validate
    parser := xarf.NewParser(false)
    report, err := parser.Parse(v4Data)
    assert.NoError(t, err)

    // Validate using validator
    validator := xarf.NewValidator()
    valid, errors := validator.ValidateReport(report)
    assert.True(t, valid, "Converted report should be valid: %v", errors)
}
```

## Common Issues

### 1. Missing Sender Field

**Issue**: v3 only has `ReporterInfo`, but v4 requires both `reporter` and `sender`.

**Solution**: The automatic converter uses the same information for both:

```go
// Automatic handling
v4Report["reporter"] = reporterInfo
v4Report["sender"] = reporterInfo
```

For third-party reporting, manually set different sender info after conversion.

### 2. Case Sensitivity

**Issue**: v3 uses mixed case (`ReportClass: "Messaging"`), v4 uses lowercase (`category: "messaging"`).

**Solution**: The converter automatically lowercases categories:

```go
category := strings.ToLower(v3Report.Report.ReportClass)
```

### 3. Missing Report ID

**Issue**: v3 reports don't have `report_id`, but v4 requires it.

**Solution**: The converter generates a new UUID v4:

```go
v4Report["report_id"] = generateSimpleUUID()
```

### 4. Timestamp Format

**Issue**: v3 date formats may vary.

**Solution**: The converter tries multiple formats:

```go
// Try RFC3339 first
timestamp, err := time.Parse(time.RFC3339, v3Report.Report.Date)
if err != nil {
    // Try alternative formats
    timestamp, err = time.Parse("2006-01-02T15:04:05Z07:00", v3Report.Report.Date)
}
```

### 5. Unknown Categories

**Issue**: v3 "Abuse" category doesn't exist in v4.

**Solution**: Mapped to "connection" by default. Manually override if needed:

```go
v4Data, _ := xarf.ConvertV3ToV4(v3Data)

// Parse the JSON to modify category
var report map[string]interface{}
json.Unmarshal(v4Data, &report)

// Override category if needed
if report["category"] == "connection" {
    report["category"] = "messaging" // Or other appropriate category
}

v4Data, _ = json.Marshal(report)
```

## Best Practices

### 1. Gradual Migration

Support both formats during a transition period:

```go
func parseReport(data []byte) (interface{}, error) {
    parser := xarf.NewParser(false)
    return parser.Parse(data) // Automatically handles v3 and v4
}
```

### 2. Log Conversions

Track when v3 reports are converted:

```go
if xarf.IsV3Report(data) {
    log.Printf("Converting v3 report to v4")
    v4Data, err := xarf.ConvertV3ToV4(data)
    // ... handle conversion
}
```

### 3. Validate After Conversion

Always validate converted reports:

```go
v4Data, err := xarf.ConvertV3ToV4(v3Data)
if err != nil {
    return err
}

validator := xarf.NewValidator()
report, _ := parser.Parse(v4Data)
valid, errors := validator.ValidateReport(report)
if !valid {
    log.Printf("Conversion produced invalid report: %v", errors)
}
```

### 4. Document Breaking Changes

If you provide APIs that accept XARF reports, document the changes:

```
API v2.0: Now accepts XARF v4 reports (v3 reports automatically converted)
- "category" field is now lowercase
- "report_id" is now required
- Separate "reporter" and "sender" fields
```

## Support

For questions or issues with migration:

- **GitHub Issues**: https://github.com/xarf/xarf-go/issues
- **Documentation**: https://pkg.go.dev/github.com/xarf/xarf-go
- **XARF Specification**: https://github.com/xarf/xarf-spec

## Further Reading

- [XARF v4 Specification](https://github.com/xarf/xarf-spec)
- [xarf-go API Documentation](https://pkg.go.dev/github.com/xarf/xarf-go)
- [CHANGELOG.md](../CHANGELOG.md) - Detailed change history
- [README.md](../README.md) - Library overview and quick start

---

Last Updated: 2025-11-30
