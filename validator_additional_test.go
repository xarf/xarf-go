package xarf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateMessagingReportMissingFields(t *testing.T) {
	validator := NewValidator()

	t.Run("missing smtp_from for smtp protocol", func(t *testing.T) {
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
			// SMTPFrom is missing
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "smtp_from")
	})

	t.Run("missing subject for spam type", func(t *testing.T) {
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
			// Subject is missing for spam type
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "subject")
	})

	t.Run("invalid messaging type", func(t *testing.T) {
		report := &MessagingReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryMessaging,
				Type:             "invalid_type",
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
			Subject:  "Test",
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "invalid messaging type")
	})
}

func TestValidateConnectionReportMissingFields(t *testing.T) {
	validator := NewValidator()

	t.Run("missing destination_ip", func(t *testing.T) {
		report := &ConnectionReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
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
			// DestinationIP is missing
			Protocol: "tcp",
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "destination_ip")
	})

	t.Run("missing protocol", func(t *testing.T) {
		report := &ConnectionReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
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
			// Protocol is missing
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "protocol")
	})
}

func TestValidateContentReportMissingURL(t *testing.T) {
	validator := NewValidator()

	report := &ContentReport{
		Report: Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryContent,
			Type:             "phishing",
			EvidenceSource:   EvidenceSourceUserReport,
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
		// URL is missing
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "url")
}

func TestValidateContentReportInvalidType(t *testing.T) {
	validator := NewValidator()

	report := &ContentReport{
		Report: Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryContent,
			Type:             "invalid_type",
			EvidenceSource:   EvidenceSourceUserReport,
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
		URL: "http://example.com",
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "invalid content type")
}

func TestValidateVulnerabilityReportInvalidCVSS(t *testing.T) {
	validator := NewValidator()

	t.Run("CVSS too high", func(t *testing.T) {
		cvss := 11.0
		report := &VulnerabilityReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryVulnerability,
				Type:             "cve",
				EvidenceSource:   EvidenceSourceVulnerabilityScan,
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
			CVSS: &cvss,
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "CVSS")
	})

	t.Run("CVSS negative", func(t *testing.T) {
		cvss := -1.0
		report := &VulnerabilityReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryVulnerability,
				Type:             "cve",
				EvidenceSource:   EvidenceSourceVulnerabilityScan,
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
			CVSS: &cvss,
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "CVSS")
	})

	t.Run("invalid vulnerability type", func(t *testing.T) {
		report := &VulnerabilityReport{
			Report: Report{
				XARFVersion:      XARFVersion,
				ReportID:         "test-123",
				Timestamp:        time.Now(),
				SourceIdentifier: "192.0.2.100",
				Category:         CategoryVulnerability,
				Type:             "invalid_type",
				EvidenceSource:   EvidenceSourceVulnerabilityScan,
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
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "invalid vulnerability type")
	})
}

func TestValidateBaseReportMissingFields(t *testing.T) {
	validator := NewValidator()

	t.Run("missing report_id", func(t *testing.T) {
		report := &Report{
			XARFVersion:      XARFVersion,
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

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "report_id")
	})

	t.Run("missing source_identifier", func(t *testing.T) {
		report := &Report{
			XARFVersion: XARFVersion,
			ReportID:    "test-123",
			Timestamp:   time.Now(),
			Category:    CategoryMessaging,
			Type:        "spam",
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

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "source_identifier")
	})

	t.Run("missing reporter org", func(t *testing.T) {
		report := &Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryMessaging,
			Type:             "spam",
			Reporter: ContactInfo{
				Contact: "test@example.com",
				Domain:  "example.com",
			},
			Sender: ContactInfo{
				Org:     "Sender Org",
				Contact: "sender@example.com",
				Domain:  "example.com",
			},
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "reporter.org")
	})

	t.Run("missing reporter contact", func(t *testing.T) {
		report := &Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryMessaging,
			Type:             "spam",
			Reporter: ContactInfo{
				Org:    "Test Org",
				Domain: "example.com",
			},
			Sender: ContactInfo{
				Org:     "Sender Org",
				Contact: "sender@example.com",
				Domain:  "example.com",
			},
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "reporter.contact")
	})

	t.Run("missing reporter domain", func(t *testing.T) {
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
			},
			Sender: ContactInfo{
				Org:     "Sender Org",
				Contact: "sender@example.com",
				Domain:  "example.com",
			},
		}

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "reporter.domain")
	})

	t.Run("invalid category", func(t *testing.T) {
		report := &Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         Category("invalid_category"),
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

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "invalid category")
	})

	t.Run("invalid evidence source", func(t *testing.T) {
		report := &Report{
			XARFVersion:      XARFVersion,
			ReportID:         "test-123",
			Timestamp:        time.Now(),
			SourceIdentifier: "192.0.2.100",
			Category:         CategoryMessaging,
			Type:             "spam",
			EvidenceSource:   EvidenceSource("invalid_source"),
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

		valid, errors := validator.ValidateReport(report)
		assert.False(t, valid)
		assert.Contains(t, errors[0], "invalid evidence_source")
	})
}

func TestValidatorIsValidIP(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		ip    string
		valid bool
	}{
		{"192.0.2.1", true},
		{"10.0.0.1", true},
		{"2001:db8::1", true},
		{"::1", true},
		{"invalid", false},
		{"256.256.256.256", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			assert.Equal(t, tt.valid, validator.isValidIP(tt.ip))
		})
	}
}

func TestValidatorIsValidURL(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		url   string
		valid bool
	}{
		{"http://example.com", true},
		{"https://example.com/path", true},
		{"ftp://files.example.com", true},
		{"example.com", false}, // No scheme
		{"://example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.valid, validator.isValidURL(tt.url))
		})
	}
}

func TestValidatorIsValidDomain(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"example.co.uk", true},
		{"a.b.c.d.example.com", true},
		{"invalid", false},
		{"", false},
		{"-invalid.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.valid, validator.isValidDomain(tt.domain))
		})
	}
}

func TestValidatorIsValidEmail(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		email string
		valid bool
	}{
		{"test@example.com", true},
		{"user.name@example.com", true},
		{"user+tag@example.com", true},
		{"invalid", false},
		{"@example.com", false},
		{"test@", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			assert.Equal(t, tt.valid, validator.isValidEmail(tt.email))
		})
	}
}
