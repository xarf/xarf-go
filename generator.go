package xarf

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"time"
)

// Generator provides functionality for generating XARF reports
type Generator struct{}

// NewGenerator creates a new Generator instance
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateUUID generates a UUID v4 for report identification
func (g *Generator) GenerateUUID() string {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return ""
	}

	// Set version (4) and variant bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// GenerateTimestamp generates an ISO 8601 formatted timestamp with UTC timezone
func (g *Generator) GenerateTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// GenerateHash generates a cryptographic hash of the provided data
func (g *Generator) GenerateHash(data []byte, algorithm string) (string, error) {
	switch algorithm {
	case "sha256":
		hash := sha256.Sum256(data)
		return hex.EncodeToString(hash[:]), nil
	case "sha512":
		hash := sha512.Sum512(data)
		return hex.EncodeToString(hash[:]), nil
	default:
		return "", NewGeneratorError(fmt.Sprintf("unsupported hash algorithm: %s", algorithm), nil)
	}
}

// AddEvidence creates an evidence item with automatic hashing
func (g *Generator) AddEvidence(contentType, description string, payload []byte, hashAlgorithm string) (*Evidence, error) {
	if hashAlgorithm == "" {
		hashAlgorithm = "sha256"
	}

	hash, err := g.GenerateHash(payload, hashAlgorithm)
	if err != nil {
		return nil, err
	}

	return &Evidence{
		ContentType: contentType,
		Description: description,
		Payload:     string(payload),
		Hash:        hash,
	}, nil
}

// ReportOptions contains options for generating a XARF report
type ReportOptions struct {
	Category         Category
	Type             string
	SourceIdentifier string
	ReporterContact  string
	ReporterOrg      string
	ReporterType     ReporterType
	EvidenceSource   EvidenceSource
	OnBehalfOf       *OnBehalfOf
	Description      string
	Evidence         []Evidence
	Severity         Severity
	Confidence       *float64
	Tags             []string
	Occurrence       *Occurrence
	Target           *Target
}

// GenerateReport generates a complete XARF v4.0.0 report
func (g *Generator) GenerateReport(opts ReportOptions) (*Report, error) {
	// Validate required fields
	if opts.SourceIdentifier == "" {
		return nil, NewGeneratorError("source_identifier is required", nil)
	}
	if opts.ReporterContact == "" {
		return nil, NewGeneratorError("reporter_contact is required", nil)
	}

	// Validate category
	if !g.isValidCategory(opts.Category) {
		return nil, NewGeneratorError(fmt.Sprintf("invalid category: %s", opts.Category), nil)
	}

	// Set defaults
	if opts.ReporterType == "" {
		opts.ReporterType = ReporterTypeAutomated
	}
	if opts.EvidenceSource == "" {
		opts.EvidenceSource = EvidenceSourceAutomatedScan
	}

	// Validate confidence if provided
	if opts.Confidence != nil {
		if *opts.Confidence < 0.0 || *opts.Confidence > 1.0 {
			return nil, NewGeneratorError("confidence must be between 0.0 and 1.0", nil)
		}
	}

	// Build report
	report := &Report{
		XARFVersion:      XARFVersion,
		ReportID:         g.GenerateUUID(),
		Timestamp:        time.Now().UTC(),
		SourceIdentifier: opts.SourceIdentifier,
		Category:         opts.Category,
		Type:             opts.Type,
		EvidenceSource:   opts.EvidenceSource,
		Reporter: Reporter{
			Org:        opts.ReporterOrg,
			Contact:    opts.ReporterContact,
			Type:       opts.ReporterType,
			OnBehalfOf: opts.OnBehalfOf,
		},
		Description: opts.Description,
		Evidence:    opts.Evidence,
		Severity:    opts.Severity,
		Confidence:  opts.Confidence,
		Tags:        opts.Tags,
		Occurrence:  opts.Occurrence,
		Target:      opts.Target,
	}

	return report, nil
}

// GenerateRandomEvidence generates random sample evidence for testing
func (g *Generator) GenerateRandomEvidence(category Category, description string) (*Evidence, error) {
	// Generate random payload data
	randomData := make([]byte, 32)
	if _, err := rand.Read(randomData); err != nil {
		return nil, NewGeneratorError("failed to generate random data", err)
	}

	// Select appropriate content type for category
	contentType := g.selectContentType(category)

	if description == "" {
		description = fmt.Sprintf("Sample %s evidence data", category)
	}

	return g.AddEvidence(contentType, description, randomData, "sha256")
}

// selectContentType selects an appropriate content type for the category
func (g *Generator) selectContentType(category Category) string {
	contentTypes := map[Category][]string{
		CategoryAbuse:          {"application/pcap", "text/plain", "image/png"},
		CategoryVulnerability:  {"text/plain", "application/json", "image/png"},
		CategoryConnection:     {"application/pcap", "text/plain", "application/json"},
		CategoryContent:        {"image/png", "text/html", "application/pdf"},
		CategoryCopyright:      {"text/html", "image/png", "application/pdf"},
		CategoryMessaging:      {"message/rfc822", "text/plain", "text/html"},
		CategoryReputation:     {"application/json", "text/plain", "text/csv"},
		CategoryInfrastructure: {"application/pcap", "text/plain", "application/json"},
	}

	types, ok := contentTypes[category]
	if !ok || len(types) == 0 {
		return "text/plain"
	}

	return types[0] // Return first type for simplicity
}

// isValidCategory checks if a category is valid
func (g *Generator) isValidCategory(category Category) bool {
	for _, c := range AllCategories() {
		if c == category {
			return true
		}
	}
	return false
}
