package xarf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateBaseReport(t *testing.T) {
	validator := NewValidator()

	report := &Report{
		XARFVersion:      XARFVersion,
		ReportID:         "test-123",
		Timestamp:        time.Now(),
		SourceIdentifier: "192.0.2.100",
		Category:         CategoryMessaging,
		Type:             "spam",
		EvidenceSource:   EvidenceSourceSpamtrap,
		Reporter: Reporter{
			Contact: "test@example.com",
			Type:    ReporterTypeAutomated,
		},
	}

	valid, errors := validator.ValidateReport(report)
	assert.True(t, valid)
	assert.Empty(t, errors)
}

func TestValidateInvalidVersion(t *testing.T) {
	validator := NewValidator()

	report := &Report{
		XARFVersion:      "3.0.0",
		ReportID:         "test-123",
		Timestamp:        time.Now(),
		SourceIdentifier: "192.0.2.100",
		Category:         CategoryMessaging,
		Type:             "spam",
		EvidenceSource:   EvidenceSourceSpamtrap,
		Reporter: Reporter{
			Contact: "test@example.com",
			Type:    ReporterTypeAutomated,
		},
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "version")
}

func TestValidateInvalidEmail(t *testing.T) {
	validator := NewValidator()

	report := &Report{
		XARFVersion:      XARFVersion,
		ReportID:         "test-123",
		Timestamp:        time.Now(),
		SourceIdentifier: "192.0.2.100",
		Category:         CategoryMessaging,
		Type:             "spam",
		EvidenceSource:   EvidenceSourceSpamtrap,
		Reporter: Reporter{
			Contact: "not-an-email",
			Type:    ReporterTypeAutomated,
		},
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "email")
}

func TestValidateConfidence(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name       string
		confidence float64
		valid      bool
	}{
		{"Valid confidence 0.5", 0.5, true},
		{"Valid confidence 0.0", 0.0, true},
		{"Valid confidence 1.0", 1.0, true},
		{"Invalid confidence -0.1", -0.1, false},
		{"Invalid confidence 1.1", 1.1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := tt.confidence
			report := &Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryMessaging,
				Type:             "spam",
				EvidenceSource:   EvidenceSourceSpamtrap,
				Reporter: Reporter{
					Contact: "test@example.com",
					Type:    ReporterTypeAutomated,
				},
				Confidence: &conf,
			}

			valid, _ := validator.ValidateReport(report)
			assert.Equal(t, tt.valid, valid)
		})
	}
}

func TestValidateMessagingReport(t *testing.T) {
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
			Reporter: Reporter{
				Contact: "test@example.com",
				Type:    ReporterTypeAutomated,
			},
		},
		Protocol: "smtp",
		SMTPFrom: "spammer@example.com",
		Subject:  "Test Spam",
	}

	valid, errors := validator.ValidateReport(report)
	assert.True(t, valid)
	assert.Empty(t, errors)
}

func TestValidateConnectionReport(t *testing.T) {
	validator := NewValidator()

	report := &ConnectionReport{
		Report: Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryConnection,
			Type:             "ddos",
			EvidenceSource:   EvidenceSourceHoneypot,
			Reporter: Reporter{
				Contact: "security@example.com",
				Type:    ReporterTypeAutomated,
			},
		},
		DestinationIP: "203.0.113.10",
		Protocol:      "tcp",
	}

	valid, errors := validator.ValidateReport(report)
	assert.True(t, valid)
	assert.Empty(t, errors)
}

func TestValidateConnectionReportInvalidIP(t *testing.T) {
	validator := NewValidator()

	report := &ConnectionReport{
		Report: Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryConnection,
			Type:             "ddos",
			EvidenceSource:   EvidenceSourceHoneypot,
			Reporter: Reporter{
				Contact: "security@example.com",
				Type:    ReporterTypeAutomated,
			},
		},
		DestinationIP: "not-an-ip",
		Protocol:      "tcp",
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "destination_ip")
}

func TestValidateContentReport(t *testing.T) {
	validator := NewValidator()

	report := &ContentReport{
		Report: Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryContent,
			Type:             "phishing_site",
			EvidenceSource:   EvidenceSourceUserReport,
			Reporter: Reporter{
				Contact: "web@example.com",
				Type:    ReporterTypeManual,
			},
		},
		URL: "http://phishing.example.com",
	}

	valid, errors := validator.ValidateReport(report)
	assert.True(t, valid)
	assert.Empty(t, errors)
}

func TestValidateContentReportInvalidURL(t *testing.T) {
	validator := NewValidator()

	report := &ContentReport{
		Report: Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryContent,
			Type:             "phishing_site",
			EvidenceSource:   EvidenceSourceUserReport,
			Reporter: Reporter{
				Contact: "web@example.com",
				Type:    ReporterTypeManual,
			},
		},
		URL: "not-a-url",
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "url")
}

func TestValidateOnBehalfOf(t *testing.T) {
	validator := NewValidator()

	report := &Report{
		XARFVersion:      XARFVersion,
		ReportID:         "test-123",
		Timestamp:        time.Now(),
		SourceIdentifier: "192.0.2.100",
		Category:         CategoryMessaging,
		Type:             "spam",
		EvidenceSource:   EvidenceSourceSpamtrap,
		Reporter: Reporter{
			Contact: "test@example.com",
			Type:    ReporterTypeAutomated,
			OnBehalfOf: &OnBehalfOf{
				Org:     "Customer Organization",
				Contact: "customer@example.com",
			},
		},
	}

	valid, errors := validator.ValidateReport(report)
	assert.True(t, valid)
	assert.Empty(t, errors)
}

func TestValidateOnBehalfOfMissingOrg(t *testing.T) {
	validator := NewValidator()

	report := &Report{
		XARFVersion:      XARFVersion,
		ReportID:         "test-123",
		Timestamp:        time.Now(),
		SourceIdentifier: "192.0.2.100",
		Category:         CategoryMessaging,
		Type:             "spam",
		EvidenceSource:   EvidenceSourceSpamtrap,
		Reporter: Reporter{
			Contact: "test@example.com",
			Type:    ReporterTypeAutomated,
			OnBehalfOf: &OnBehalfOf{
				Contact: "customer@example.com",
			},
		},
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "on_behalf_of.org")
}

func TestValidateVulnerabilityReport(t *testing.T) {
	validator := NewValidator()

	cvss := 7.5
	report := &VulnerabilityReport{
		Report: Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryVulnerability,
			Type:             "cve",
			EvidenceSource:   EvidenceSourceVulnerabilityScan,
			Reporter: Reporter{
				Contact: "security@example.com",
				Type:    ReporterTypeAutomated,
			},
		},
		CVE:  "CVE-2024-1234",
		CVSS: &cvss,
	}

	valid, errors := validator.ValidateReport(report)
	assert.True(t, valid)
	assert.Empty(t, errors)
}
