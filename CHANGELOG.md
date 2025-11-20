# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of XARF Go library
- Support for XARF v4.0.0 specification
- Parser for all 8 XARF report categories
- Validator with comprehensive validation rules
- Generator for creating compliant XARF reports
- Support for on-behalf-of reporting
- Comprehensive test suite with >90% coverage
- GitHub Actions CI/CD workflows
- golangci-lint configuration
- Makefile for build automation
- Complete API documentation

### Categories Supported
- Abuse
- Messaging
- Connection
- Content
- Copyright
- Infrastructure
- Vulnerability
- Reputation

### Features
- Type-safe Go structs for all report types
- Automatic category detection during parsing
- Email, IP, and URL validation
- Evidence hash generation (SHA-256, SHA-512)
- UUID v4 report ID generation
- ISO 8601 timestamp generation
- Confidence score validation
- CVSS score validation
- Comprehensive error types

## [1.0.0] - TBD

### Added
- First stable release

[Unreleased]: https://github.com/xarf/xarf-go/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/xarf/xarf-go/releases/tag/v1.0.0
