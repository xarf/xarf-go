package xarf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateUUIDUniqueness(t *testing.T) {
	gen := NewGenerator()

	// Generate multiple UUIDs and ensure they're unique
	uuids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		uuid := gen.GenerateUUID()
		assert.False(t, uuids[uuid], "UUID should be unique")
		uuids[uuid] = true
	}
}

func TestAddEvidenceInvalidHash(t *testing.T) {
	gen := NewGenerator()
	payload := []byte("test data")

	_, err := gen.AddEvidence("text/plain", "Test", payload, "invalid_algorithm")
	assert.Error(t, err)
}

func TestGenerateRandomEvidenceAllCategories(t *testing.T) {
	gen := NewGenerator()

	categories := []Category{
		CategoryMessaging,
		CategoryConnection,
		CategoryContent,
		CategoryAbuse,
		CategoryVulnerability,
		CategoryCopyright,
		CategoryInfrastructure,
		CategoryReputation,
	}

	for _, category := range categories {
		t.Run(string(category), func(t *testing.T) {
			evidence, err := gen.GenerateRandomEvidence(category, "Test evidence")
			require.NoError(t, err)
			assert.NotEmpty(t, evidence.ContentType)
			assert.NotEmpty(t, evidence.Payload)
			assert.NotEmpty(t, evidence.Hash)
		})
	}
}

func TestSelectContentTypeForEachCategory(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		category     Category
		expectedType string
	}{
		{CategoryMessaging, "message/rfc822"},
		{CategoryConnection, "application/pcap"},
		{CategoryContent, "image/png"},
		{CategoryAbuse, "application/pcap"},
		{CategoryVulnerability, "text/plain"},
		{CategoryCopyright, "text/html"},
		{CategoryInfrastructure, "application/pcap"},
		{CategoryReputation, "application/json"},
		{Category("unknown"), "text/plain"},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			contentType := gen.selectContentType(tt.category)
			assert.Equal(t, tt.expectedType, contentType)
		})
	}
}

func TestIsValidCategoryAllTypes(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		category Category
		expected bool
	}{
		{CategoryMessaging, true},
		{CategoryConnection, true},
		{CategoryContent, true},
		{CategoryAbuse, true},
		{CategoryVulnerability, true},
		{CategoryCopyright, true},
		{CategoryInfrastructure, true},
		{CategoryReputation, true},
		{Category("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			assert.Equal(t, tt.expected, gen.isValidCategory(tt.category))
		})
	}
}

func TestGenerateReportInvalidCategory(t *testing.T) {
	gen := NewGenerator()

	opts := ReportOptions{
		Category:         Category("invalid_category"),
		Type:             "test",
		SourceIdentifier: "192.0.2.100",
		Reporter: ContactInfo{
			Org:     "Test Org",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: ContactInfo{
			Org:     "Sender Org",
			Contact: "sender@example.com",
			Domain:  "example.com",
		},
	}

	_, err := gen.GenerateReport(&opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid category")
}

func TestGenerateReportWithAllOptionalFields(t *testing.T) {
	gen := NewGenerator()

	confidence := 0.85
	opts := ReportOptions{
		Category:         CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		Reporter: ContactInfo{
			Org:     "Test Org",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: ContactInfo{
			Org:     "Client Org",
			Contact: "client@example.com",
			Domain:  "example.com",
		},
		Severity:    SeverityMedium,
		Confidence:  &confidence,
		Tags:        []string{"tag1", "tag2", "tag3"},
		Description: "Detailed description",
	}

	report, err := gen.GenerateReport(&opts)
	require.NoError(t, err)

	assert.Equal(t, "Test Org", report.Reporter.Org)
	assert.Equal(t, "Client Org", report.Sender.Org)
	assert.Equal(t, SeverityMedium, report.Severity)
	assert.Equal(t, 0.85, *report.Confidence)
	assert.Equal(t, []string{"tag1", "tag2", "tag3"}, report.Tags)
	assert.Equal(t, "Detailed description", report.Description)
}

func TestGenerateReportMinimalFields(t *testing.T) {
	gen := NewGenerator()

	opts := ReportOptions{
		Category:         CategoryConnection,
		Type:             "ddos",
		SourceIdentifier: "192.0.2.100",
		Reporter: ContactInfo{
			Org:     "Test Org",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: ContactInfo{
			Org:     "Sender Org",
			Contact: "sender@example.com",
			Domain:  "example.com",
		},
	}

	report, err := gen.GenerateReport(&opts)
	require.NoError(t, err)

	assert.Equal(t, XARFVersion, report.XARFVersion)
	assert.NotEmpty(t, report.ReportID)
	assert.NotEmpty(t, report.Timestamp)
	assert.Equal(t, CategoryConnection, report.Category)
	assert.Equal(t, "ddos", report.Type)
	assert.Equal(t, "abuse@example.com", report.Reporter.Contact)
	assert.Equal(t, "example.com", report.Reporter.Domain)
}

func TestGenerateHashDifferentAlgorithms(t *testing.T) {
	gen := NewGenerator()
	data := []byte("test data for hashing")

	sha256Hash, err := gen.GenerateHash(data, "sha256")
	require.NoError(t, err)
	assert.Len(t, sha256Hash, 64)

	sha512Hash, err := gen.GenerateHash(data, "sha512")
	require.NoError(t, err)
	assert.Len(t, sha512Hash, 128)

	// Verify hashes are different for different algorithms
	assert.NotEqual(t, sha256Hash, sha512Hash)
}

func TestAddEvidenceEmptyPayload(t *testing.T) {
	gen := NewGenerator()
	emptyPayload := []byte{}

	evidence, err := gen.AddEvidence("text/plain", "Empty evidence", emptyPayload, "sha256")
	require.NoError(t, err)

	assert.Equal(t, "text/plain", evidence.ContentType)
	assert.Equal(t, "Empty evidence", evidence.Description)
	assert.NotEmpty(t, evidence.Hash)
}

func TestGenerateRandomEvidencePayloadNotEmpty(t *testing.T) {
	gen := NewGenerator()

	evidence, err := gen.GenerateRandomEvidence(CategoryMessaging, "Random test")
	require.NoError(t, err)

	// Verify payload is not empty and has reasonable size
	assert.NotEmpty(t, evidence.Payload)
	assert.Greater(t, len(evidence.Payload), 0)
}
