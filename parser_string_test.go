package xarf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseString(t *testing.T) {
	jsonStr := `{
		"xarf_version": "4.0.0",
		"report_id": "test-123",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {
			"org": "Test Org",
			"contact": "test@example.com",
			"domain": "example.com"
		},
		"sender": {
			"org": "Sender Org",
			"contact": "sender@example.com",
			"domain": "example.com"
		},
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
		"evidence_source": "spamtrap",
		"protocol": "smtp",
		"smtp_from": "spammer@example.com",
		"subject": "Test Spam"
	}`

	parser := NewParser(false)
	result, err := parser.ParseString(jsonStr)
	require.NoError(t, err)

	report, ok := result.(*MessagingReport)
	require.True(t, ok)
	assert.Equal(t, CategoryMessaging, report.Category)
	assert.Equal(t, "spam", report.Type)
}

func TestParseStringInvalid(t *testing.T) {
	invalidJSON := "{invalid json}"

	parser := NewParser(true)
	_, err := parser.ParseString(invalidJSON)
	require.Error(t, err)

	parseErr, ok := err.(*ParseError)
	require.True(t, ok)
	assert.Contains(t, parseErr.Message, "invalid JSON")
}

func TestValidateString(t *testing.T) {
	validJSON := `{
		"xarf_version": "4.0.0",
		"report_id": "test-123",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {
			"org": "Test Org",
			"contact": "test@example.com",
			"domain": "example.com"
		},
		"sender": {
			"org": "Sender Org",
			"contact": "sender@example.com",
			"domain": "example.com"
		},
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
		"evidence_source": "spamtrap"
	}`

	parser := NewParser(false)
	valid := parser.ValidateString(validJSON)
	assert.True(t, valid)
	assert.Empty(t, parser.GetErrors())
}

func TestValidateStringInvalid(t *testing.T) {
	invalidJSON := `{
		"xarf_version": "4.0.0",
		"category": "messaging"
	}`

	parser := NewParser(false)
	valid := parser.ValidateString(invalidJSON)
	assert.False(t, valid)
	assert.NotEmpty(t, parser.GetErrors())
}

func TestParseByCategoryUnknown(t *testing.T) {
	jsonStr := `{
		"xarf_version": "4.0.0",
		"report_id": "test-123",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {
			"org": "Test Org",
			"contact": "test@example.com",
			"domain": "example.com"
		},
		"sender": {
			"org": "Sender Org",
			"contact": "sender@example.com",
			"domain": "example.com"
		},
		"source_identifier": "192.0.2.100",
		"category": "unknown_category",
		"type": "test",
		"evidence_source": "automated_scan"
	}`

	parser := NewParser(false)
	result, err := parser.ParseString(jsonStr)
	require.NoError(t, err)

	// Should fall back to base Report
	report, ok := result.(*Report)
	require.True(t, ok)
	assert.Equal(t, Category("unknown_category"), report.Category)
}
