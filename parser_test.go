package xarf

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseValidMessagingReport(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"timestamp":    "2024-01-15T10:30:00Z",
		"reporter": map[string]interface{}{
			"org":     "Test Org",
			"contact": "test@example.com",
			"domain":  "example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Sender Org",
			"contact": "sender@example.com",
			"domain":  "example.com",
		},
		"source_identifier": "192.0.2.100",
		"category":          "messaging",
		"type":              "spam",
		"evidence_source":   "spamtrap",
		"protocol":          "smtp",
		"smtp_from":         "spammer@example.com",
		"subject":           "Test Spam",
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(false)
	result, err := parser.Parse(jsonData)
	require.NoError(t, err)

	report, ok := result.(*MessagingReport)
	require.True(t, ok, "Expected MessagingReport type")

	assert.Equal(t, CategoryMessaging, report.Category)
	assert.Equal(t, "spam", report.Type)
	assert.Equal(t, "spammer@example.com", report.SMTPFrom)
	assert.Equal(t, "Test Spam", report.Subject)
}

func TestParseValidConnectionReport(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "b2c3d4e5-f6g7-8901-bcde-f1234567890a",
		"timestamp":    "2024-01-15T11:00:00Z",
		"reporter": map[string]interface{}{
			"org":     "Security Monitor",
			"contact": "security@example.com",
			"domain":  "example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Sender Org",
			"contact": "sender@example.com",
			"domain":  "example.com",
		},
		"source_identifier": "192.0.2.200",
		"category":          "connection",
		"type":              "ddos",
		"evidence_source":   "honeypot",
		"destination_ip":    "203.0.113.10",
		"protocol":          "tcp",
		"destination_port":  80,
		"attack_type":       "syn_flood",
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(false)
	result, err := parser.Parse(jsonData)
	require.NoError(t, err)

	report, ok := result.(*ConnectionReport)
	require.True(t, ok, "Expected ConnectionReport type")

	assert.Equal(t, CategoryConnection, report.Category)
	assert.Equal(t, "ddos", report.Type)
	assert.Equal(t, "203.0.113.10", report.DestinationIP)
	assert.Equal(t, "tcp", report.Protocol)
}

func TestParseValidContentReport(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "c3d4e5f6-g7h8-9012-cdef-234567890abc",
		"timestamp":    "2024-01-15T12:00:00Z",
		"reporter": map[string]interface{}{
			"org":     "Web Security",
			"contact": "web@example.com",
			"domain":  "example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Sender Org",
			"contact": "sender@example.com",
			"domain":  "example.com",
		},
		"source_identifier": "192.0.2.300",
		"category":          "content",
		"type":              "phishing_site",
		"evidence_source":   "user_report",
		"url":               "http://phishing.example.com",
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(false)
	result, err := parser.Parse(jsonData)
	require.NoError(t, err)

	report, ok := result.(*ContentReport)
	require.True(t, ok, "Expected ContentReport type")

	assert.Equal(t, CategoryContent, report.Category)
	assert.Equal(t, "phishing_site", report.Type)
	assert.Equal(t, "http://phishing.example.com", report.URL)
}

func TestParseWithSameOrg(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "test-123",
		"timestamp":    "2024-01-15T10:30:00Z",
		"reporter": map[string]interface{}{
			"org":     "Example Org",
			"contact": "abuse@example.com",
			"domain":  "example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Example Org",
			"contact": "sender@example.com",
			"domain":  "example.com",
		},
		"source_identifier": "192.0.2.100",
		"category":          "messaging",
		"type":              "spam",
		"evidence_source":   "spamtrap",
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(false)
	result, err := parser.Parse(jsonData)
	require.NoError(t, err)

	report, ok := result.(*MessagingReport)
	require.True(t, ok)
	assert.Equal(t, "Example Org", report.Reporter.Org)
	assert.Equal(t, "Example Org", report.Sender.Org)
}

func TestParseWithDifferentOrg(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "test-123",
		"timestamp":    "2024-01-15T10:30:00Z",
		"reporter": map[string]interface{}{
			"org":     "Service Provider",
			"contact": "abuse@provider.com",
			"domain":  "provider.com",
		},
		"sender": map[string]interface{}{
			"org":     "Customer Organization",
			"contact": "customer@example.com",
			"domain":  "example.com",
		},
		"source_identifier": "192.0.2.100",
		"category":          "messaging",
		"type":              "spam",
		"evidence_source":   "spamtrap",
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(false)
	result, err := parser.Parse(jsonData)
	require.NoError(t, err)

	report, ok := result.(*MessagingReport)
	require.True(t, ok)
	assert.Equal(t, "Service Provider", report.Reporter.Org)
	assert.Equal(t, "Customer Organization", report.Sender.Org)
}

func TestParseInvalidJSON(t *testing.T) {
	invalidJSON := []byte("{invalid json}")

	parser := NewParser(true)
	_, err := parser.Parse(invalidJSON)
	require.Error(t, err)

	parseErr, ok := err.(*ParseError)
	require.True(t, ok, "Expected ParseError")
	assert.Contains(t, parseErr.Message, "invalid JSON")
}

func TestParseMissingRequiredFields(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"category":     "messaging",
		// Missing required fields (report_id, reporter, sender, etc.)
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(true)
	_, err = parser.Parse(jsonData)
	require.Error(t, err)

	validationErr, ok := err.(*ValidationError)
	require.True(t, ok, "Expected ValidationError")
	assert.NotEmpty(t, validationErr.Errors)
}

func TestParseInvalidVersion(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "3.0.0",
		"report_id":    "test-123",
		"timestamp":    "2024-01-15T10:30:00Z",
		"reporter": map[string]interface{}{
			"org":     "Test Org",
			"contact": "test@example.com",
			"domain":  "example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Sender Org",
			"contact": "sender@example.com",
			"domain":  "example.com",
		},
		"source_identifier": "192.0.2.100",
		"category":          "messaging",
		"type":              "spam",
		"evidence_source":   "spamtrap",
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(true)
	_, err = parser.Parse(jsonData)
	require.Error(t, err)

	validationErr, ok := err.(*ValidationError)
	require.True(t, ok)
	assert.Contains(t, validationErr.Error(), "version")
}

func TestValidate(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "test-123",
		"timestamp":    "2024-01-15T10:30:00Z",
		"reporter": map[string]interface{}{
			"org":     "Test Org",
			"contact": "test@example.com",
			"domain":  "example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Sender Org",
			"contact": "sender@example.com",
			"domain":  "example.com",
		},
		"source_identifier": "192.0.2.100",
		"category":          "messaging",
		"type":              "spam",
		"evidence_source":   "spamtrap",
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(false)
	valid := parser.Validate(jsonData)
	assert.True(t, valid)
	assert.Empty(t, parser.GetErrors())
}

func TestValidateInvalid(t *testing.T) {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		// Missing required fields
	}

	jsonData, err := json.Marshal(reportData)
	require.NoError(t, err)

	parser := NewParser(false)
	valid := parser.Validate(jsonData)
	assert.False(t, valid)
	assert.NotEmpty(t, parser.GetErrors())
}

func TestParseAllCategories(t *testing.T) {
	categories := []struct {
		category    Category
		reportType  string
		extraFields map[string]interface{}
	}{
		{CategoryMessaging, "spam", nil},
		{CategoryConnection, "ddos", map[string]interface{}{"destination_ip": "203.0.113.10", "protocol": "tcp"}},
		{CategoryContent, "phishing_site", map[string]interface{}{"url": "http://example.com"}},
		{CategoryCopyright, "infringement", nil},
		{CategoryInfrastructure, "botnet", nil},
		{CategoryVulnerability, "cve", nil},
		{CategoryReputation, "blocklist", nil},
	}

	for _, tc := range categories {
		t.Run(string(tc.category), func(t *testing.T) {
			reportData := map[string]interface{}{
				"xarf_version": "4.2.0",
				"report_id":    "test-123",
				"timestamp":    "2024-01-15T10:30:00Z",
				"reporter": map[string]interface{}{
					"org":     "Test Org",
					"contact": "test@example.com",
					"domain":  "example.com",
				},
				"sender": map[string]interface{}{
					"org":     "Sender Org",
					"contact": "sender@example.com",
					"domain":  "example.com",
				},
				"source_identifier": "192.0.2.100",
				"category":          string(tc.category),
				"type":              tc.reportType,
				"evidence_source":   "automated_scan",
			}

			// Add extra required fields
			for k, v := range tc.extraFields {
				reportData[k] = v
			}

			jsonData, err := json.Marshal(reportData)
			require.NoError(t, err)

			parser := NewParser(false)
			result, err := parser.Parse(jsonData)
			require.NoError(t, err)
			require.NotNil(t, result)
		})
	}
}
