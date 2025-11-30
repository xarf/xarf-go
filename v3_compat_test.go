package xarf

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsV3Report(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		{
			name: "Valid v3 report",
			data: `{
				"Version": "3.0.0",
				"ReporterInfo": {
					"ReporterOrg": "Test Org"
				}
			}`,
			expected: true,
		},
		{
			name: "V3 with different version",
			data: `{
				"Version": "3.1.0",
				"ReporterInfo": {}
			}`,
			expected: true,
		},
		{
			name: "V4 report",
			data: `{
				"xarf_version": "4.0.0",
				"reporter": {}
			}`,
			expected: false,
		},
		{
			name: "Invalid JSON",
			data: `{invalid}`,
			expected: false,
		},
		{
			name: "No version field",
			data: `{"other": "data"}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsV3Report([]byte(tt.data))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertV3ToV4_Messaging(t *testing.T) {
	v3Data := []byte(`{
		"Version": "3.0.0",
		"ReporterInfo": {
			"ReporterOrg": "Security Team",
			"ReporterOrgDomain": "example.com",
			"ReporterOrgEmail": "abuse@example.com"
		},
		"Report": {
			"ReportClass": "Messaging",
			"ReportType": "spam",
			"SourceIP": "192.0.2.100",
			"Date": "2024-01-15T10:30:00Z",
			"EvidenceSource": "spamtrap",
			"Description": "Spam email detected",
			"SMTPFrom": "spammer@bad.com",
			"Subject": "Spam subject"
		}
	}`)

	v4Data, err := ConvertV3ToV4(v3Data)
	assert.NoError(t, err)
	assert.NotNil(t, v4Data)

	// Parse as v4 to verify structure
	var v4Report map[string]interface{}
	err = json.Unmarshal(v4Data, &v4Report)
	assert.NoError(t, err)

	// Verify core fields
	assert.Equal(t, XARFVersion, v4Report["xarf_version"])
	assert.Equal(t, "messaging", v4Report["category"])
	assert.Equal(t, "spam", v4Report["type"])
	assert.Equal(t, "192.0.2.100", v4Report["source_identifier"])
	assert.Equal(t, "spamtrap", v4Report["evidence_source"])
	assert.Equal(t, "Spam email detected", v4Report["description"])

	// Verify reporter
	reporter := v4Report["reporter"].(map[string]interface{})
	assert.Equal(t, "Security Team", reporter["org"])
	assert.Equal(t, "abuse@example.com", reporter["contact"])
	assert.Equal(t, "example.com", reporter["domain"])

	// Verify sender (should be same as reporter)
	sender := v4Report["sender"].(map[string]interface{})
	assert.Equal(t, "Security Team", sender["org"])

	// Verify additional fields were preserved
	assert.Equal(t, "spammer@bad.com", v4Report["smtp_from"])
	assert.Equal(t, "Spam subject", v4Report["subject"])
}

func TestConvertV3ToV4_Connection(t *testing.T) {
	v3Data := []byte(`{
		"Version": "3.0.0",
		"ReporterInfo": {
			"ReporterOrg": "ISP Security",
			"ReporterOrgDomain": "isp.com",
			"ReporterOrgEmail": "security@isp.com"
		},
		"Report": {
			"ReportClass": "Connection",
			"ReportType": "ddos",
			"SourceIP": "203.0.113.50",
			"Date": "2024-01-15T14:20:00Z",
			"DestinationIP": "198.51.100.10",
			"Protocol": "tcp",
			"DestinationPort": 80
		}
	}`)

	v4Data, err := ConvertV3ToV4(v3Data)
	assert.NoError(t, err)

	var v4Report map[string]interface{}
	json.Unmarshal(v4Data, &v4Report)

	assert.Equal(t, "connection", v4Report["category"])
	assert.Equal(t, "ddos", v4Report["type"])
	assert.Equal(t, "198.51.100.10", v4Report["destination_ip"])
	assert.Equal(t, "tcp", v4Report["protocol"])
	assert.Equal(t, float64(80), v4Report["destination_port"]) // JSON numbers are float64
}

func TestConvertV3ToV4_Content(t *testing.T) {
	v3Data := []byte(`{
		"Version": "3.0.0",
		"ReporterInfo": {
			"ReporterOrg": "Web Security",
			"ReporterOrgDomain": "websec.org",
			"ReporterOrgEmail": "reports@websec.org"
		},
		"Report": {
			"ReportClass": "Content",
			"ReportType": "phishing_site",
			"SourceIP": "192.0.2.200",
			"Date": "2024-01-16T09:00:00Z",
			"URL": "http://phishing.example",
			"ContentType": "text/html"
		}
	}`)

	v4Data, err := ConvertV3ToV4(v3Data)
	assert.NoError(t, err)

	var v4Report map[string]interface{}
	json.Unmarshal(v4Data, &v4Report)

	assert.Equal(t, "content", v4Report["category"])
	assert.Equal(t, "phishing_site", v4Report["type"])
	assert.Equal(t, "http://phishing.example", v4Report["url"])
	assert.Equal(t, "text/html", v4Report["content_type"])
}

func TestConvertV3ToV4_AllCategories(t *testing.T) {
	categories := map[string]string{
		"Messaging":      "messaging",
		"Connection":     "connection",
		"Content":        "content",
		"Copyright":      "copyright",
		"Infrastructure": "infrastructure",
		"Vulnerability":  "vulnerability",
		"Reputation":     "reputation",
		"Abuse":          "connection", // v3 Abuse maps to v4 connection
	}

	for v3Cat, v4Cat := range categories {
		t.Run(v3Cat, func(t *testing.T) {
			v3Data := []byte(`{
				"Version": "3.0.0",
				"ReporterInfo": {
					"ReporterOrg": "Test Org",
					"ReporterOrgDomain": "test.com",
					"ReporterOrgEmail": "test@test.com"
				},
				"Report": {
					"ReportClass": "` + v3Cat + `",
					"ReportType": "test_type",
					"SourceIP": "192.0.2.1",
					"Date": "2024-01-15T10:00:00Z"
				}
			}`)

			v4Data, err := ConvertV3ToV4(v3Data)
			assert.NoError(t, err)

			var v4Report map[string]interface{}
			json.Unmarshal(v4Data, &v4Report)

			assert.Equal(t, v4Cat, v4Report["category"])
		})
	}
}

func TestParseV3Report(t *testing.T) {
	v3Data := []byte(`{
		"Version": "3.0.0",
		"ReporterInfo": {
			"ReporterOrg": "Security Team",
			"ReporterOrgDomain": "example.com",
			"ReporterOrgEmail": "abuse@example.com"
		},
		"Report": {
			"ReportClass": "Messaging",
			"ReportType": "spam",
			"SourceIP": "192.0.2.100",
			"Date": "2024-01-15T10:30:00Z",
			"EvidenceSource": "spamtrap"
		}
	}`)

	report, err := ParseV3Report(v3Data)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	// Should be parsed as MessagingReport
	msgReport, ok := report.(*MessagingReport)
	assert.True(t, ok, "Should be MessagingReport type")
	assert.Equal(t, CategoryMessaging, msgReport.Category)
	assert.Equal(t, "spam", msgReport.Type)
}

func TestGetV4Category(t *testing.T) {
	tests := []struct {
		v3Category string
		expected   string
	}{
		{"Messaging", "messaging"},
		{"Connection", "connection"},
		{"Content", "content"},
		{"Copyright", "copyright"},
		{"Infrastructure", "infrastructure"},
		{"Vulnerability", "vulnerability"},
		{"Reputation", "reputation"},
		{"Abuse", "connection"}, // Special mapping
		{"Unknown", "unknown"},  // Fallback to lowercase
	}

	for _, tt := range tests {
		t.Run(tt.v3Category, func(t *testing.T) {
			result := GetV4Category(tt.v3Category)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertV3ToV4_MissingOptionalFields(t *testing.T) {
	v3Data := []byte(`{
		"Version": "3.0.0",
		"ReporterInfo": {
			"ReporterOrg": "Test Org",
			"ReporterOrgDomain": "test.com",
			"ReporterOrgEmail": "test@test.com"
		},
		"Report": {
			"ReportClass": "Connection",
			"ReportType": "ddos",
			"SourceIP": "192.0.2.1"
		}
	}`)

	v4Data, err := ConvertV3ToV4(v3Data)
	assert.NoError(t, err)

	var v4Report map[string]interface{}
	json.Unmarshal(v4Data, &v4Report)

	// Should have generated timestamp
	assert.NotEmpty(t, v4Report["timestamp"])

	// Should have generated report_id
	assert.NotEmpty(t, v4Report["report_id"])

	// Should have default evidence_source
	assert.Equal(t, "automated_scan", v4Report["evidence_source"])
}

func TestReportGetCategory(t *testing.T) {
	report := &Report{
		Category: CategoryMessaging,
	}

	category := report.GetCategory()
	assert.Equal(t, "messaging", category)
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"SMTPFrom", "smtp_from"},
		{"DestinationIP", "destination_ip"},
		{"URL", "url"},
		{"simple", "simple"},
		{"ReportClass", "report_class"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toSnakeCase(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapV3EvidenceSource(t *testing.T) {
	tests := []struct {
		v3Source string
		expected string
	}{
		{"spamtrap", "spamtrap"},
		{"honeypot", "honeypot"},
		{"user_report", "user_report"},
		{"automated_scan", "automated_scan"},
		{"unknown_source", "automated_scan"}, // Default
		{"", "automated_scan"},                // Default
	}

	for _, tt := range tests {
		t.Run(tt.v3Source, func(t *testing.T) {
			result := mapV3EvidenceSource(tt.v3Source)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertV3ToV4_Integration(t *testing.T) {
	// Full integration test: v3 to v4 conversion and parsing
	v3Data := []byte(`{
		"Version": "3.0.0",
		"ReporterInfo": {
			"ReporterOrg": "Example ISP",
			"ReporterOrgDomain": "isp.example",
			"ReporterOrgEmail": "abuse@isp.example"
		},
		"Report": {
			"ReportClass": "Connection",
			"ReportType": "port_scan",
			"SourceIP": "198.51.100.50",
			"Date": "2024-01-15T10:30:00Z",
			"EvidenceSource": "honeypot",
			"Description": "Port scan detected",
			"DestinationIP": "203.0.113.10",
			"Protocol": "tcp",
			"DestinationPort": 22
		}
	}`)

	// Convert v3 to v4
	v4Data, err := ConvertV3ToV4(v3Data)
	assert.NoError(t, err)

	// Parse as v4
	parser := NewParser(false)
	report, err := parser.Parse(v4Data)
	assert.NoError(t, err)
	assert.NotNil(t, report)

	// Verify it's a ConnectionReport
	connReport, ok := report.(*ConnectionReport)
	assert.True(t, ok)
	assert.Equal(t, CategoryConnection, connReport.Category)
	assert.Equal(t, "port_scan", connReport.Type)
	assert.Equal(t, "198.51.100.50", connReport.SourceIdentifier)
	assert.Equal(t, "203.0.113.10", connReport.DestinationIP)
	assert.Equal(t, "tcp", connReport.Protocol)

	// Validate the converted report
	validator := NewValidator()
	valid, errors := validator.ValidateReport(report)
	assert.True(t, valid, "Converted report should be valid: %v", errors)
}

func TestParserAutoDetectV3(t *testing.T) {
	// Test that Parser.Parse() automatically handles v3 reports
	v3Data := []byte(`{
		"Version": "3.0.0",
		"ReporterInfo": {
			"ReporterOrg": "Auto Detect Test",
			"ReporterOrgDomain": "test.example",
			"ReporterOrgEmail": "test@test.example"
		},
		"Report": {
			"ReportClass": "Messaging",
			"ReportType": "spam",
			"SourceIP": "192.0.2.150",
			"Date": "2024-01-15T10:30:00Z",
			"EvidenceSource": "spamtrap"
		}
	}`)

	// First check if it's detected as v3
	assert.True(t, IsV3Report(v3Data))

	// Note: Current parser doesn't auto-convert v3, this would require
	// modifying parser.Parse() to check IsV3Report() first
	// For now, we use ParseV3Report() explicitly
	report, err := ParseV3Report(v3Data)
	assert.NoError(t, err)
	assert.NotNil(t, report)
}
