package xarf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateUUID(t *testing.T) {
	gen := NewGenerator()
	uuid := gen.GenerateUUID()

	assert.NotEmpty(t, uuid)
	assert.Len(t, uuid, 36) // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
}

func TestGenerateTimestamp(t *testing.T) {
	gen := NewGenerator()
	timestamp := gen.GenerateTimestamp()

	assert.NotEmpty(t, timestamp)
	assert.Contains(t, timestamp, "T") // ISO 8601 format
}

func TestGenerateHash(t *testing.T) {
	gen := NewGenerator()
	data := []byte("test data")

	tests := []struct {
		algorithm string
		length    int
		wantErr   bool
	}{
		{"sha256", 64, false},
		{"sha512", 128, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			hash, err := gen.GenerateHash(data, tt.algorithm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, hash, tt.length)
			}
		})
	}
}

func TestAddEvidence(t *testing.T) {
	gen := NewGenerator()
	payload := []byte("sample evidence data")

	evidence, err := gen.AddEvidence("text/plain", "Test evidence", payload, "sha256")
	require.NoError(t, err)

	assert.Equal(t, "text/plain", evidence.ContentType)
	assert.Equal(t, "Test evidence", evidence.Description)
	assert.NotEmpty(t, evidence.Hash)
	assert.Len(t, evidence.Hash, 64) // SHA-256 produces 64 hex characters
}

func TestGenerateReport(t *testing.T) {
	gen := NewGenerator()

	opts := ReportOptions{
		Category:         CategoryConnection,
		Type:             "ddos",
		SourceIdentifier: "192.0.2.100",
		ReporterContact:  "abuse@example.com",
		ReporterOrg:      "Example Security",
		Description:      "Test DDoS report",
	}

	report, err := gen.GenerateReport(opts)
	require.NoError(t, err)

	assert.Equal(t, XARFVersion, report.XARFVersion)
	assert.NotEmpty(t, report.ReportID)
	assert.Equal(t, CategoryConnection, report.Category)
	assert.Equal(t, "ddos", report.Type)
	assert.Equal(t, "192.0.2.100", report.SourceIdentifier)
	assert.Equal(t, "abuse@example.com", report.Reporter.Contact)
	assert.Equal(t, "Example Security", report.Reporter.Org)
}

func TestGenerateReportWithOnBehalfOf(t *testing.T) {
	gen := NewGenerator()

	opts := ReportOptions{
		Category:         CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		ReporterContact:  "abuse@provider.com",
		ReporterOrg:      "Service Provider",
		OnBehalfOf: &OnBehalfOf{
			Org:     "Customer Organization",
			Contact: "customer@example.com",
		},
	}

	report, err := gen.GenerateReport(opts)
	require.NoError(t, err)

	require.NotNil(t, report.Reporter.OnBehalfOf)
	assert.Equal(t, "Customer Organization", report.Reporter.OnBehalfOf.Org)
	assert.Equal(t, "customer@example.com", report.Reporter.OnBehalfOf.Contact)
}

func TestGenerateReportWithOptions(t *testing.T) {
	gen := NewGenerator()

	confidence := 0.95
	opts := ReportOptions{
		Category:         CategoryContent,
		Type:             "phishing_site",
		SourceIdentifier: "192.0.2.100",
		ReporterContact:  "abuse@example.com",
		Severity:         SeverityHigh,
		Confidence:       &confidence,
		Tags:             []string{"phishing", "urgent"},
	}

	report, err := gen.GenerateReport(opts)
	require.NoError(t, err)

	assert.Equal(t, SeverityHigh, report.Severity)
	assert.Equal(t, 0.95, *report.Confidence)
	assert.Equal(t, []string{"phishing", "urgent"}, report.Tags)
}

func TestGenerateReportMissingRequired(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		name string
		opts ReportOptions
	}{
		{
			"Missing source_identifier",
			ReportOptions{
				Category:        CategoryMessaging,
				Type:            "spam",
				ReporterContact: "abuse@example.com",
			},
		},
		{
			"Missing reporter_contact",
			ReportOptions{
				Category:         CategoryMessaging,
				Type:             "spam",
				SourceIdentifier: "192.0.2.100",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gen.GenerateReport(tt.opts)
			assert.Error(t, err)
		})
	}
}

func TestGenerateReportInvalidConfidence(t *testing.T) {
	gen := NewGenerator()

	confidence := 1.5
	opts := ReportOptions{
		Category:         CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		ReporterContact:  "abuse@example.com",
		Confidence:       &confidence,
	}

	_, err := gen.GenerateReport(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "confidence")
}

func TestGenerateRandomEvidence(t *testing.T) {
	gen := NewGenerator()

	evidence, err := gen.GenerateRandomEvidence(CategoryConnection, "Random test evidence")
	require.NoError(t, err)

	assert.NotEmpty(t, evidence.ContentType)
	assert.Equal(t, "Random test evidence", evidence.Description)
	assert.NotEmpty(t, evidence.Payload)
	assert.NotEmpty(t, evidence.Hash)
}

func TestGenerateReportAllCategories(t *testing.T) {
	gen := NewGenerator()

	categories := []struct {
		category   Category
		reportType string
	}{
		{CategoryAbuse, "ddos"},
		{CategoryMessaging, "spam"},
		{CategoryConnection, "ddos"},
		{CategoryContent, "phishing_site"},
		{CategoryCopyright, "infringement"},
		{CategoryInfrastructure, "botnet"},
		{CategoryVulnerability, "cve"},
		{CategoryReputation, "blocklist"},
	}

	for _, tc := range categories {
		t.Run(string(tc.category), func(t *testing.T) {
			opts := ReportOptions{
				Category:         tc.category,
				Type:             tc.reportType,
				SourceIdentifier: "192.0.2.100",
				ReporterContact:  "abuse@example.com",
			}

			report, err := gen.GenerateReport(opts)
			require.NoError(t, err)
			assert.Equal(t, tc.category, report.Category)
			assert.Equal(t, tc.reportType, report.Type)
		})
	}
}
