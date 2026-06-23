package xarf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSchemaValidator(t *testing.T) {
	// Reset to ensure clean state
	ResetSchemaValidator()

	validator := GetSchemaValidator()
	require.NotNil(t, validator)

	// Should return same instance (singleton)
	validator2 := GetSchemaValidator()
	assert.Same(t, validator, validator2)
}

func TestSchemaValidatorIsLoaded(t *testing.T) {
	ResetSchemaValidator()
	validator := GetSchemaValidator()

	// Should be loaded after initialization
	assert.True(t, validator.IsLoaded())
}

func TestSchemaValidatorValidateJSON(t *testing.T) {
	ResetSchemaValidator()
	validator := GetSchemaValidator()

	tests := []struct {
		name      string
		json      string
		wantValid bool
	}{
		{
			name: "valid minimal report",
			json: `{
				"xarf_version": "4.2.0",
				"report_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				"timestamp": "2026-01-19T12:00:00Z",
				"source_identifier": "192.0.2.100",
				"source_port": 25,
				"category": "messaging",
				"type": "spam",
				"protocol": "smtp",
				"smtp_from": "spammer@example.com",
				"reporter": {
					"org": "Test Org",
					"contact": "test@example.com",
					"domain": "example.com"
				},
				"sender": {
					"org": "Sender Org",
					"contact": "sender@example.com",
					"domain": "example.com"
				}
			}`,
			wantValid: true,
		},
		{
			name:      "invalid JSON",
			json:      `{invalid json`,
			wantValid: false,
		},
		{
			name:      "empty JSON object",
			json:      `{}`,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateJSON(tt.json)
			assert.Equal(t, tt.wantValid, result.Valid)
			if !tt.wantValid {
				assert.NotEmpty(t, result.Errors)
			}
		})
	}
}

func TestSchemaValidatorValidateReport(t *testing.T) {
	ResetSchemaValidator()
	validator := GetSchemaValidator()

	sourcePort := 25

	t.Run("valid messaging report (base fields)", func(t *testing.T) {
		report := &MessagingReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				SourcePort:       &sourcePort,
				Category:         CategoryMessaging,
				Type:             "spam",
				EvidenceSource:   EvidenceSourceSpamtrap,
				Reporter: ContactInfo{
					Org:     "Test Org",
					Contact: "test@example.com",
					Domain:  "example.com",
				},
				Sender: ContactInfo{
					Org:     "Sender Org",
					Contact: "sender@example.com",
					Domain:  "example.com",
				},
			},
			Protocol: "smtp",
			SMTPFrom: "spammer@example.com",
		}

		result := validator.ValidateReport(report)
		assert.True(t, result.Valid, "errors: %v", result.Errors)
	})

	t.Run("valid messaging report", func(t *testing.T) {
		report := &MessagingReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "b2c3d4e5-f6a7-8901-bcde-f1234567890a",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				SourcePort:       &sourcePort,
				Category:         CategoryMessaging,
				Type:             "spam",
				EvidenceSource:   EvidenceSourceSpamtrap,
				Reporter: ContactInfo{
					Org:     "Test Org",
					Contact: "test@example.com",
					Domain:  "example.com",
				},
				Sender: ContactInfo{
					Org:     "Sender Org",
					Contact: "sender@example.com",
					Domain:  "example.com",
				},
			},
			Protocol: "smtp",
			SMTPFrom: "spammer@example.com",
		}

		result := validator.ValidateReport(report)
		assert.True(t, result.Valid, "errors: %v", result.Errors)
	})

	t.Run("valid connection report", func(t *testing.T) {
		connSourcePort := 12345
		report := &ConnectionReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "c3d4e5f6-a7b8-9012-cdef-234567890abc",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryConnection,
				Type:             "ddos",
				EvidenceSource:   EvidenceSourceHoneypot,
				Reporter: ContactInfo{
					Org:     "Test Org",
					Contact: "test@example.com",
					Domain:  "example.com",
				},
				Sender: ContactInfo{
					Org:     "Sender Org",
					Contact: "sender@example.com",
					Domain:  "example.com",
				},
			},
			DestinationIP: "203.0.113.10",
			Protocol:      "tcp",
			FirstSeen:     "2026-01-19T12:00:00Z",
			SourcePort:    &connSourcePort,
		}

		result := validator.ValidateReport(report)
		assert.True(t, result.Valid, "errors: %v", result.Errors)
	})
}

func TestSchemaValidatorValidateJSONWithTypeSchema(t *testing.T) {
	ResetSchemaValidator()
	validator := GetSchemaValidator()

	// Test with a report that has category and type for type-specific validation
	json := `{
		"xarf_version": "4.2.0",
		"report_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"timestamp": "2026-01-19T12:00:00Z",
		"source_identifier": "192.0.2.100",
		"source_port": 25,
		"category": "messaging",
		"type": "spam",
		"protocol": "smtp",
		"smtp_from": "spammer@example.com",
		"reporter": {
			"org": "Test Org",
			"contact": "test@example.com",
			"domain": "example.com"
		},
		"sender": {
			"org": "Sender Org",
			"contact": "sender@example.com",
			"domain": "example.com"
		}
	}`

	result := validator.ValidateJSON(json)
	assert.True(t, result.Valid)
}

func TestResetSchemaValidator(t *testing.T) {
	// Get initial instance
	validator1 := GetSchemaValidator()
	require.NotNil(t, validator1)

	// Reset
	ResetSchemaValidator()

	// Get new instance - should be different
	validator2 := GetSchemaValidator()
	require.NotNil(t, validator2)

	// Both should be loaded
	assert.True(t, validator1.IsLoaded())
	assert.True(t, validator2.IsLoaded())
}

func TestValidationResultStruct(t *testing.T) {
	t.Run("valid result", func(t *testing.T) {
		result := ValidationResult{
			Valid:  true,
			Errors: nil,
		}
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("invalid result with errors", func(t *testing.T) {
		result := ValidationResult{
			Valid:  false,
			Errors: []string{"error 1", "error 2"},
		}
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 2)
	})
}
