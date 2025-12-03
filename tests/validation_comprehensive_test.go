package tests

import (
	"testing"
	"time"

	"github.com/xarf/xarf-go"
)

// TestValidatorAllCategories ensures validator works for all 7 categories
func TestValidatorAllCategories(t *testing.T) {
	validator := xarf.NewValidator()

	now := time.Now().UTC()

	categories := []struct {
		category   xarf.Category
		reportType string
	}{
		{xarf.CategoryMessaging, "spam"},
		{xarf.CategoryConnection, "ddos"},
		{xarf.CategoryContent, "phishing"},
		{xarf.CategoryCopyright, "p2p"},
		{xarf.CategoryInfrastructure, "botnet"},
		{xarf.CategoryVulnerability, "cve"},
		{xarf.CategoryReputation, "blocklist"},
	}

	for _, tc := range categories {
		t.Run(string(tc.category), func(t *testing.T) {
			report := &xarf.Report{
				XARFVersion:      "4.0.0",
				ReportID:         "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:        now,
				Category:         tc.category,
				Type:             tc.reportType,
				SourceIdentifier: "192.0.2.100",
				Reporter: xarf.ContactInfo{
					Org:     "Test Org",
					Contact: "test@example.com",
					Domain:  "example.com",
				},
				Sender: xarf.ContactInfo{
					Org:     "Sender Org",
					Contact: "sender@example.com",
					Domain:  "example.com",
				},
				EvidenceSource: xarf.EvidenceSourceAutomatedScan,
			}

			valid, errors := validator.ValidateReport(report)
			if !valid {
				t.Errorf("Category %s validation failed: %v", tc.category, errors)
			}
			if len(errors) > 0 {
				t.Errorf("Category %s has validation errors: %v", tc.category, errors)
			}
		})
	}
}

// TestInvalidCategory ensures invalid categories are rejected
func TestInvalidCategory(t *testing.T) {
	validator := xarf.NewValidator()

	now := time.Now().UTC()

	report := &xarf.Report{
		XARFVersion:      "4.0.0",
		ReportID:         "550e8400-e29b-41d4-a716-446655440000",
		Timestamp:        now,
		Category:         "invalid_category",
		Type:             "test",
		SourceIdentifier: "192.0.2.100",
		Reporter: xarf.ContactInfo{
			Org:     "Test",
			Contact: "test@example.com",
			Domain:  "example.com",
		},
		Sender: xarf.ContactInfo{
			Org:     "Sender",
			Contact: "sender@example.com",
			Domain:  "example.com",
		},
	}

	valid, errors := validator.ValidateReport(report)
	if valid {
		t.Error("Should reject invalid category")
	}
	if len(errors) == 0 {
		t.Error("Should return validation errors")
	}
}

// TestValidatorCategorySpecificFields tests category-specific validation
func TestValidatorCategorySpecificFields(t *testing.T) {
	validator := xarf.NewValidator()
	now := time.Now().UTC()

	// Connection report should validate destination_ip
	destPort := 80
	connReport := &xarf.ConnectionReport{
		Report: xarf.Report{
			XARFVersion:      "4.0.0",
			ReportID:         "550e8400-e29b-41d4-a716-446655440000",
			Timestamp:        now,
			Category:         xarf.CategoryConnection,
			Type:             "ddos",
			SourceIdentifier: "192.0.2.100",
			Reporter: xarf.ContactInfo{
				Org:     "Test",
				Contact: "test@example.com",
				Domain:  "example.com",
			},
			Sender: xarf.ContactInfo{
				Org:     "Sender",
				Contact: "sender@example.com",
				Domain:  "example.com",
			},
			EvidenceSource: xarf.EvidenceSourceAutomatedScan,
		},
		DestinationIP:   "203.0.113.10",
		Protocol:        "tcp",
		DestinationPort: &destPort,
	}

	valid, errors := validator.ValidateReport(&connReport.Report)
	if !valid {
		t.Errorf("Connection report validation failed: %v", errors)
	}
}

// TestValidatorMissingRequiredFields tests validation of missing required fields
func TestValidatorMissingRequiredFields(t *testing.T) {
	validator := xarf.NewValidator()

	tests := []struct {
		name   string
		report *xarf.Report
	}{
		{
			name: "Missing XARFVersion",
			report: &xarf.Report{
				ReportID:         "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:        time.Now(),
				Category:         xarf.CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
			},
		},
		{
			name: "Missing ReportID",
			report: &xarf.Report{
				XARFVersion:      "4.0.0",
				Timestamp:        time.Now(),
				Category:         xarf.CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
			},
		},
		{
			name: "Missing Category",
			report: &xarf.Report{
				XARFVersion:      "4.0.0",
				ReportID:         "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:        time.Now(),
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
			},
		},
		{
			name: "Missing SourceIdentifier",
			report: &xarf.Report{
				XARFVersion: "4.0.0",
				ReportID:    "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:   time.Now(),
				Category:    xarf.CategoryMessaging,
				Type:        "spam",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, errors := validator.ValidateReport(tt.report)
			if valid {
				t.Error("Should reject report with missing required fields")
			}
			if len(errors) == 0 {
				t.Error("Should return validation errors")
			}
		})
	}
}

// TestValidatorInvalidFieldValues tests validation of invalid field values
func TestValidatorInvalidFieldValues(t *testing.T) {
	validator := xarf.NewValidator()
	now := time.Now().UTC()

	tests := []struct {
		name   string
		report *xarf.Report
	}{
		{
			name: "Invalid confidence > 1.0",
			report: &xarf.Report{
				XARFVersion:      "4.0.0",
				ReportID:         "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:        now,
				Category:         xarf.CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
				Confidence:       floatPtr(1.5),
			},
		},
		{
			name: "Invalid confidence < 0.0",
			report: &xarf.Report{
				XARFVersion:      "4.0.0",
				ReportID:         "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:        now,
				Category:         xarf.CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
				Confidence:       floatPtr(-0.5),
			},
		},
		{
			name: "Invalid UUID format",
			report: &xarf.Report{
				XARFVersion:      "4.0.0",
				ReportID:         "not-a-uuid",
				Timestamp:        now,
				Category:         xarf.CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, errors := validator.ValidateReport(tt.report)
			if valid {
				t.Error("Should reject report with invalid field values")
			}
			if len(errors) == 0 {
				t.Error("Should return validation errors")
			}
		})
	}
}

// TestValidatorOptionalFields tests that optional fields don't cause validation failures
func TestValidatorOptionalFields(t *testing.T) {
	validator := xarf.NewValidator()
	now := time.Now().UTC()

	// Report with all optional fields filled
	report := &xarf.Report{
		XARFVersion:      "4.0.0",
		ReportID:         "550e8400-e29b-41d4-a716-446655440000",
		Timestamp:        now,
		Category:         xarf.CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		Reporter: xarf.ContactInfo{
			Org:     "Test Org",
			Contact: "test@example.com",
			Domain:  "example.com",
		},
		Sender: xarf.ContactInfo{
			Org:     "Sender Org",
			Contact: "sender@example.com",
			Domain:  "example.com",
		},
		EvidenceSource: xarf.EvidenceSourceSpamtrap,
		Description:    "Test description",
		Evidence: []xarf.Evidence{
			{
				ContentType: "text/plain",
				Description: "Sample evidence",
				Payload:     "Evidence data",
			},
		},
		Severity:   xarf.SeverityHigh,
		Confidence: floatPtr(0.95),
		Tags:       []string{"test", "spam"},
	}

	valid, errors := validator.ValidateReport(report)
	if !valid {
		t.Errorf("Validation failed: %v", errors)
	}
}

// TestValidatorSeverityLevels tests all severity levels
func TestValidatorSeverityLevels(t *testing.T) {
	validator := xarf.NewValidator()
	now := time.Now().UTC()

	severities := []xarf.Severity{
		xarf.SeverityLow,
		xarf.SeverityMedium,
		xarf.SeverityHigh,
		xarf.SeverityCritical,
	}

	for _, severity := range severities {
		t.Run(string(severity), func(t *testing.T) {
			report := &xarf.Report{
				XARFVersion:      "4.0.0",
				ReportID:         "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:        now,
				Category:         xarf.CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
				Reporter: xarf.ContactInfo{
					Org:     "Test",
					Contact: "test@example.com",
					Domain:  "example.com",
				},
				Sender: xarf.ContactInfo{
					Org:     "Sender",
					Contact: "sender@example.com",
					Domain:  "example.com",
				},
				EvidenceSource: xarf.EvidenceSourceAutomatedScan,
				Severity:       severity,
			}

			valid, errors := validator.ValidateReport(report)
			if !valid {
				t.Errorf("Severity %s validation failed: %v", severity, errors)
			}
		})
	}
}

// TestValidatorEvidenceSources tests all evidence source types
func TestValidatorEvidenceSources(t *testing.T) {
	validator := xarf.NewValidator()
	now := time.Now().UTC()

	sources := []xarf.EvidenceSource{
		xarf.EvidenceSourceSpamtrap,
		xarf.EvidenceSourceHoneypot,
		xarf.EvidenceSourceUserReport,
		xarf.EvidenceSourceAutomatedScan,
		xarf.EvidenceSourceManualAnalysis,
		xarf.EvidenceSourceVulnerabilityScan,
		xarf.EvidenceSourceResearcherAnalysis,
		xarf.EvidenceSourceThreatIntelligence,
		xarf.EvidenceSourceFlowAnalysis,
		xarf.EvidenceSourceIDSIPS,
		xarf.EvidenceSourceSIEM,
	}

	for _, source := range sources {
		t.Run(string(source), func(t *testing.T) {
			report := &xarf.Report{
				XARFVersion:      "4.0.0",
				ReportID:         "550e8400-e29b-41d4-a716-446655440000",
				Timestamp:        now,
				Category:         xarf.CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
				Reporter: xarf.ContactInfo{
					Org:     "Test",
					Contact: "test@example.com",
					Domain:  "example.com",
				},
				Sender: xarf.ContactInfo{
					Org:     "Sender",
					Contact: "sender@example.com",
					Domain:  "example.com",
				},
				EvidenceSource: source,
			}

			valid, errors := validator.ValidateReport(report)
			if !valid {
				t.Errorf("Evidence source %s validation failed: %v", source, errors)
			}
		})
	}
}

// floatPtr returns a pointer to a float64 value
func floatPtr(f float64) *float64 {
	return &f
}
