package xarf

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateEvidenceConstraints(t *testing.T) {
	t.Run("Valid evidence within limits", func(t *testing.T) {
		validator := NewValidator()
		evidence := []Evidence{
			{
				ContentType: "text/plain",
				Description: "Test evidence",
				Payload:     "Small payload",
			},
		}
		valid := validator.validateEvidenceConstraints(evidence)
		assert.True(t, valid)
		assert.Empty(t, validator.GetErrors())
	})

	t.Run("Evidence count exceeds maximum", func(t *testing.T) {
		validator := NewValidator()
		evidence := make([]Evidence, MaxEvidenceCount+1)
		for i := range evidence {
			evidence[i] = Evidence{
				ContentType: "text/plain",
				Description: "Test",
				Payload:     "data",
			}
		}
		valid := validator.validateEvidenceConstraints(evidence)
		assert.False(t, valid)
		errors := validator.GetErrors()
		assert.Contains(t, errors[0], "evidence count exceeds maximum")
	})

	t.Run("Evidence payload exceeds size limit", func(t *testing.T) {
		validator := NewValidator()
		largePayload := strings.Repeat("A", MaxEvidenceSize+1)
		evidence := []Evidence{
			{
				ContentType: "text/plain",
				Description: "Large payload",
				Payload:     largePayload,
			},
		}
		valid := validator.validateEvidenceConstraints(evidence)
		assert.False(t, valid)
		errors := validator.GetErrors()
		assert.Contains(t, errors[0], "payload exceeds maximum size")
	})

	t.Run("Evidence missing content_type", func(t *testing.T) {
		validator := NewValidator()
		evidence := []Evidence{
			{
				ContentType: "", // Missing
				Description: "Test",
				Payload:     "data",
			},
		}
		valid := validator.validateEvidenceConstraints(evidence)
		assert.False(t, valid)
		errors := validator.GetErrors()
		assert.Contains(t, errors[0], "must have a content_type")
	})

	t.Run("Multiple evidence validation errors", func(t *testing.T) {
		validator := NewValidator()
		evidence := []Evidence{
			{
				ContentType: "",
				Description: "Missing content type",
				Payload:     "data",
			},
			{
				ContentType: "text/plain",
				Description: "Too large",
				Payload:     strings.Repeat("B", MaxEvidenceSize+1),
			},
		}
		valid := validator.validateEvidenceConstraints(evidence)
		assert.False(t, valid)
		errors := validator.GetErrors()
		assert.GreaterOrEqual(t, len(errors), 2)
	})

	t.Run("Empty evidence list", func(t *testing.T) {
		validator := NewValidator()
		evidence := []Evidence{}
		valid := validator.validateEvidenceConstraints(evidence)
		assert.True(t, valid)
		assert.Empty(t, validator.GetErrors())
	})
}

func TestValidateReportWithEvidenceConstraints(t *testing.T) {
	t.Run("Report with valid evidence", func(t *testing.T) {
		validator := NewValidator()
		report := &MessagingReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryMessaging,
				Type:             "spam",
				EvidenceSource:   EvidenceSourceSpamtrap,
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
				Evidence: []Evidence{
					{
						ContentType: "message/rfc822",
						Description: "Spam email",
						Payload:     "Email headers and body",
					},
				},
			},
			Protocol: "smtp",
			SMTPFrom: "spammer@evil.com",
			Subject:  "Spam message",
		}

		valid, errors := validator.ValidateReport(report)
		assert.True(t, valid)
		assert.Empty(t, errors)
	})

	t.Run("Report with evidence exceeding count limit", func(t *testing.T) {
		validator := NewValidator()
		evidence := make([]Evidence, MaxEvidenceCount+1)
		for i := range evidence {
			evidence[i] = Evidence{
				ContentType: "text/plain",
				Description: "Evidence item",
				Payload:     "data",
			}
		}

		report := &MessagingReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryMessaging,
				Type:             "spam",
				EvidenceSource:   EvidenceSourceSpamtrap,
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
				Evidence: evidence,
			},
			Protocol: "smtp",
			SMTPFrom: "spammer@evil.com",
			Subject:  "Spam message",
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.NotEmpty(t, errors)
		assert.Contains(t, errors[0], "evidence count exceeds maximum")
	})

	t.Run("Report with evidence exceeding size limit", func(t *testing.T) {
		validator := NewValidator()
		report := &MessagingReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryMessaging,
				Type:             "spam",
				EvidenceSource:   EvidenceSourceSpamtrap,
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
				Evidence: []Evidence{
					{
						ContentType: "application/octet-stream",
						Description: "Large binary data",
						Payload:     strings.Repeat("X", MaxEvidenceSize+1),
					},
				},
			},
			Protocol: "smtp",
			SMTPFrom: "spammer@evil.com",
			Subject:  "Spam message",
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.NotEmpty(t, errors)
		found := false
		for _, err := range errors {
			if strings.Contains(err, "payload exceeds maximum size") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should contain payload size error")
	})
}
