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
				"xarf_version": "4.0.0",
				"report_id": "test-123",
				"timestamp": "2026-01-19T12:00:00Z",
				"source_identifier": "192.0.2.100",
				"category": "messaging",
				"type": "spam",
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

	t.Run("valid base report", func(t *testing.T) {
		report := &Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryMessaging,
			Type:             "spam",
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
		}

		result := validator.ValidateReport(report)
		assert.True(t, result.Valid)
	})

	t.Run("valid messaging report", func(t *testing.T) {
		report := &MessagingReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-456",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryMessaging,
				Type:             "spam",
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
		assert.True(t, result.Valid)
	})

	t.Run("valid connection report", func(t *testing.T) {
		report := &ConnectionReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-789",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryConnection,
				Type:             "ddos",
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
		}

		result := validator.ValidateReport(report)
		assert.True(t, result.Valid)
	})
}

func TestSchemaValidatorValidateJSONWithTypeSchema(t *testing.T) {
	ResetSchemaValidator()
	validator := GetSchemaValidator()

	// Test with a report that has category and type for type-specific validation
	json := `{
		"xarf_version": "4.0.0",
		"report_id": "test-123",
		"timestamp": "2026-01-19T12:00:00Z",
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
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
