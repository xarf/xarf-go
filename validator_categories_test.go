package xarf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateAbusiveReport(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		reportType  string
		expectValid bool
	}{
		{"Valid ddos", "ddos", true},
		{"Valid malware", "malware", true},
		{"Valid phishing", "phishing", true},
		{"Valid spam", "spam", true},
		{"Valid scanner", "scanner", true},
		{"Invalid type", "invalid_type", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &AbusiveReport{
				Report: Report{
					XARFVersion:      XARFVersion,
					ReportID:         "test-123",
					Timestamp:        time.Now(),
					SourceIdentifier: "192.0.2.100",
					Category:         CategoryAbuse,
					Type:             tt.reportType,
					EvidenceSource:   EvidenceSourceAutomatedScan,
					Reporter: Reporter{
						Contact: "abuse@example.com",
						Type:    ReporterTypeAutomated,
					},
				},
			}

			valid, _ := validator.ValidateReport(report)
			assert.Equal(t, tt.expectValid, valid)
		})
	}
}

func TestValidateCopyrightReport(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		reportType  string
		expectValid bool
	}{
		{"Valid infringement", "infringement", true},
		{"Valid dmca", "dmca", true},
		{"Valid trademark", "trademark", true},
		{"Valid p2p", "p2p", true},
		{"Valid cyberlocker", "cyberlocker", true},
		{"Valid link_site", "link_site", true},
		{"Valid ugc_platform", "ugc_platform", true},
		{"Valid usenet", "usenet", true},
		{"Valid copyright", "copyright", true},
		{"Invalid type", "invalid_type", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &CopyrightReport{
				Report: Report{
					XARFVersion:      XARFVersion,
					ReportID:         "test-123",
					Timestamp:        time.Now(),
					SourceIdentifier: "192.0.2.100",
					Category:         CategoryCopyright,
					Type:             tt.reportType,
					EvidenceSource:   EvidenceSourceUserReport,
					Reporter: Reporter{
						Contact: "copyright@example.com",
						Type:    ReporterTypeManual,
					},
				},
			}

			valid, _ := validator.ValidateReport(report)
			assert.Equal(t, tt.expectValid, valid)
		})
	}
}

func TestValidateInfrastructureReport(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		reportType  string
		expectValid bool
	}{
		{"Valid botnet", "botnet", true},
		{"Valid compromised_server", "compromised_server", true},
		{"Invalid type", "invalid_type", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &InfrastructureReport{
				Report: Report{
					XARFVersion:      XARFVersion,
					ReportID:         "test-123",
					Timestamp:        time.Now(),
					SourceIdentifier: "192.0.2.100",
					Category:         CategoryInfrastructure,
					Type:             tt.reportType,
					EvidenceSource:   EvidenceSourceThreatIntelligence,
					Reporter: Reporter{
						Contact: "security@example.com",
						Type:    ReporterTypeAutomated,
					},
				},
			}

			valid, _ := validator.ValidateReport(report)
			assert.Equal(t, tt.expectValid, valid)
		})
	}
}

func TestValidateReputationReport(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		reportType  string
		expectValid bool
	}{
		{"Valid blocklist", "blocklist", true},
		{"Valid threat_intelligence", "threat_intelligence", true},
		{"Invalid type", "invalid_type", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ReputationReport{
				Report: Report{
					XARFVersion:      XARFVersion,
					ReportID:         "test-123",
					Timestamp:        time.Now(),
					SourceIdentifier: "192.0.2.100",
					Category:         CategoryReputation,
					Type:             tt.reportType,
					EvidenceSource:   EvidenceSourceThreatIntelligence,
					Reporter: Reporter{
						Contact: "intel@example.com",
						Type:    ReporterTypeAutomated,
					},
				},
			}

			valid, _ := validator.ValidateReport(report)
			assert.Equal(t, tt.expectValid, valid)
		})
	}
}

func TestValidateReputationReportThreatScore(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		threatScore *float64
		expectValid bool
	}{
		{"Valid score 0.5", floatPtr(0.5), true},
		{"Valid score 0.0", floatPtr(0.0), true},
		{"Valid score 1.0", floatPtr(1.0), true},
		{"Invalid score -0.1", floatPtr(-0.1), false},
		{"Invalid score 1.5", floatPtr(1.5), false},
		{"No score", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ReputationReport{
				Report: Report{
					XARFVersion:      XARFVersion,
					ReportID:         "test-123",
					Timestamp:        time.Now(),
					SourceIdentifier: "192.0.2.100",
					Category:         CategoryReputation,
					Type:             "blocklist",
					EvidenceSource:   EvidenceSourceThreatIntelligence,
					Reporter: Reporter{
						Contact: "intel@example.com",
						Type:    ReporterTypeAutomated,
					},
				},
				ThreatScore: tt.threatScore,
			}

			valid, _ := validator.ValidateReport(report)
			assert.Equal(t, tt.expectValid, valid)
		})
	}
}

func TestValidateUnknownReportType(t *testing.T) {
	validator := NewValidator()

	// Pass an unsupported report type
	type UnknownReport struct {
		Report
	}

	report := &UnknownReport{
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
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "unknown report type")
}

func TestIsValidSeverity(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		severity Severity
		expected bool
	}{
		{SeverityLow, true},
		{SeverityMedium, true},
		{SeverityHigh, true},
		{SeverityCritical, true},
		{Severity("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			assert.Equal(t, tt.expected, validator.isValidSeverity(tt.severity))
		})
	}
}

func TestValidateBaseReportSeverity(t *testing.T) {
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
		Severity: Severity("invalid_severity"),
	}

	valid, errors := validator.ValidateReport(report)
	assert.False(t, valid)
	assert.Contains(t, errors[0], "invalid severity")
}

// Helper function
func floatPtr(f float64) *float64 {
	return &f
}
