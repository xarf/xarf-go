# Changelog

All notable changes to the xarf-go library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-06-30

### Fixed

- **v3→v4 conversion now accepts the deployed XARF v3 dialect.** The converter
  recognized only the JavaScript library's spellings; production v3 traffic uses
  the v3-schema spellings, which were rejected. Specifically:
  - Added schema spellings `DOS`, `PortScan`, `LoginAttack` as aliases for
    `ddos`/`port_scan`/`login_attack` (the hyphenated JS spellings are retained).
  - `extractV3SourceIdentifier` and content conversion now read `SourceUrl` (the
    schema-canonical URL field for content reports such as Phishing/Malware) —
    fixes "missing URL for content type" on real reports that carry only `SourceUrl`.
  - Messaging and connection conversion no longer hard-error when the v3 report
    has no `Protocol` field (the v3 schema defines none); they default to `smtp`
    and `tcp` respectively (with a warning) so the converted v4 report satisfies
    the v4.2.0 type-required `protocol` field.
- **`Parse` no longer returns a Go error when a detected v3 report fails to
  convert.** Such a report is a validation failure, so the message is now returned
  in `ParseResult.Errors`, matching the documented contract that a Go error is
  reserved for invalid JSON or `MaxInputBytes` overflow.
- **v3 evidence samples are no longer silently dropped.** `convertV3Evidence`
  read `att["Data"]`, but the v3 schema names the field `Payload`, so every
  converted report carried empty evidence (`payload:""`, `size:0`). It now reads
  `Payload` (with `Data` as a dialect fallback), honors `Base64Encoded` to decide
  whether the source is already base64, and emits a v4 `evidence_item` whose
  `payload` is base64-encoded with `hash`/`size` over the decoded bytes. The
  source array is now `Report.Samples` first (schema-canonical), then `Attachment`.
- **`Copyright` reports now convert.** A `CategoryCopyright` case maps the v3
  `SourceUrl` to the v4 `copyright/copyright` required field `infringing_url`
  (and `InfringedMaterial` → `work_title`); previously copyright reports converted
  to a v4 doc missing `infringing_url` and failed validation.
- **`description` is read from the schema field `ReporterNotes`** (the converter
  previously read a non-existent `AttackDescription`, so descriptions were always
  empty); `AttackDescription` is retained as a fallback.
- **Connection `first_seen` prefers the v3 `FirstSeen` field**, falling back to
  the report `Date`.

### Notes

- The v3 ReportTypes `ChildAbuse`, `Trademark`, `Exploit`, `OpenService`,
  `WebCrawler`, and `PotentiallyCompromisedAccount` remain unmapped: they have no
  v4.2.0 type, or their v4 type requires fields the converter cannot derive from
  v3 data. They produce a clear "unknown ReportType" error rather than an invalid
  v4 document. Mapping them is tracked for a follow-up change.
- `Botnet` still maps to `infrastructure/botnet`, whose v4.2.0 schema requires
  `compromise_evidence` — a field with no v3 equivalent — so botnet reports
  convert but fail v4 validation until that mapping is resolved.

## [1.1.0] - 2026-06-23

Behavioural parity with the official JavaScript library ([`@xarf/xarf`](https://www.npmjs.com/package/@xarf/xarf)).

### Changed

- **XARF spec upgraded to v4.2.0.** Embedded schemas refreshed to the v4.2.0
  set (byte-identical to the JavaScript library); `XARFVersion`/`SpecVersion`
  are now `4.2.0`. Validation is now performed against the self-contained
  master schema (core + every category/type schema), matching JS — this is
  stricter than before (type-specific required fields and valid category/type
  combinations are enforced).
- **Evidence format**: `Evidence.Payload` is now base64-encoded, `Evidence.Hash`
  is algorithm-prefixed (`"sha256:<hex>"`), and a `Size` field was added —
  matching `createEvidence()` in the JS library.

### Added

- **Package-level `Parse` / `ParseString`** returning `ParseResult{Report,
  Errors, Warnings, Info}`. v3 reports are auto-detected and converted (with a
  deprecation warning); validation failures are returned in `Errors` rather than
  as a Go error (an error is returned only for malformed JSON or input exceeding
  `ParseOptions.MaxInputBytes`). Supports `Strict` and `ShowMissingOptional`.
- **`CreateReport`** (auto-fills `xarf_version`, `report_id`, `timestamp`) and
  **`CreateEvidence`** (base64 payload, prefixed hash, size; sha256/sha512/sha1/md5).
- **JS-mirror v3 helpers**: `IsXARFv3`, `ConvertV3toV4`, `GetV3DeprecationWarning`,
  matching the JS detection and type-mapping semantics.
- **Strict mode** promotes `x-recommended` schema fields to required, and reports
  unknown fields as warnings (errors in strict mode).
- Version exports: `BundledSpecVersion` and `Version`.

## [1.0.0] - 2025-11-30

### Added
- **XARF v3 Backwards Compatibility**: Full support for parsing and converting legacy XARF v3 reports to v4 format
  - `IsV3Report()` function to detect v3 format reports
  - `ConvertV3ToV4()` function for transparent v3 to v4 conversion
  - `ParseV3Report()` convenience function for parsing v3 reports
  - Automatic field mapping between v3 and v4 schemas
  - Support for all v3 categories with proper v4 mapping
- Comprehensive validation for all 7 XARF v4 categories
- Type-safe structs for all category-specific reports
- Third-party reporting support with separate reporter/sender fields
- Evidence source enumeration with 11 standard types
- Severity levels (low, medium, high, critical)
- Confidence scoring (0.0-1.0)
- Occurrence time ranges for incidents
- Target information (IP, port, URL)
- Evidence attachments with automatic hashing (SHA256, SHA512)
- UUID v4 generation for report IDs
- RFC3339 timestamp generation
- Comprehensive test coverage

### Changed
- **BREAKING**: Removed "abuse" category (not in XARF v4.0.0 specification)
  - The library now correctly implements only the 7 official categories
  - Migration path: Use "connection" category for reports previously using "abuse"
- Updated to production-ready v1.0.0 version
- Aligned with XARF v4.0.0 specification requirements
- Improved category validation to match specification exactly

### Removed
- **BREAKING**: `CategoryAbuse` constant (use `CategoryConnection` instead)
- **BREAKING**: `AbusiveReport` struct type (use `ConnectionReport` instead)
- **BREAKING**: Abuse category validation and parsing logic

### Fixed
- Category list now correctly contains only 7 categories as per specification
- All documentation updated to reflect correct category count

### Migration Notes

#### From v0.x to v1.0.0

**Removed Abuse Category:**
If your code uses the "abuse" category, update it to use "connection":

```go
// Old (v0.x)
opts := xarf.ReportOptions{
    Category: xarf.CategoryAbuse,
    Type:     "ddos",
    // ...
}

// New (v1.0.0)
opts := xarf.ReportOptions{
    Category: xarf.CategoryConnection,
    Type:     "ddos",
    // ...
}
```

**Abuse Report Type:**
If your code uses `AbusiveReport`, switch to `ConnectionReport`:

```go
// Old (v0.x)
var report *xarf.AbusiveReport

// New (v1.0.0)
var report *xarf.ConnectionReport
```

#### From XARF v3 to v4

The library automatically handles v3 reports through conversion. No code changes needed for parsing:

```go
// Works with both v3 and v4 reports
parser := xarf.NewParser(false)
report, err := parser.Parse(jsonData) // Automatically detects and converts v3
```

For explicit v3 conversion:

```go
if xarf.IsV3Report(data) {
    v4Data, err := xarf.ConvertV3ToV4(data)
    // Use v4Data
}
```

### Security
- See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting

## Version Numbering

This library uses independent semantic versioning starting from v1.0.0:
- **Library Version**: v1.0.0
- **XARF Specification**: v4.0.0

The library version evolves independently of the XARF specification version to allow for library-specific improvements and bug fixes.

[1.0.0]: https://github.com/xarf/xarf-go/releases/tag/v1.0.0
