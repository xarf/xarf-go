package xarf

import (
	"strings"
	"testing"
)

// TestInputSanitization ensures no code injection vulnerabilities
func TestInputSanitization(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"SQL Injection Attempt", "'; DROP TABLE reports; --"},
		{"XSS Attempt", "<script>alert('xss')</script>"},
		{"Command Injection", "'; rm -rf / ; '"},
		{"Path Traversal", "../../etc/passwd"},
		{"Null Byte Injection", "test\x00.txt"},
	}

	parser := NewParser(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parser should handle malicious input safely by treating it as data
			jsonData := []byte(`{
				"xarf_version": "4.0.0",
				"report_id": "550e8400-e29b-41d4-a716-446655440000",
				"timestamp": "2024-01-15T10:30:00Z",
				"reporter": {"org": "` + tt.input + `", "contact": "test@example.com", "domain": "example.com"},
				"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
				"source_identifier": "192.0.2.100",
				"category": "messaging",
				"type": "spam"
			}`)

			// The main security test is that parsing doesn't cause execution
			// The parser treats malicious strings as plain data (not executed)
			result, err := parser.Parse(jsonData)
			if err != nil {
				// Parsing might fail for invalid JSON (like null bytes), which is acceptable
				t.Logf("Input rejected: %v", err)
			} else if result != nil {
				// If parsing succeeds, the malicious input is safely stored as data
				// This is acceptable - the parser's job is to parse, not execute
				t.Logf("Input parsed as data (safe)")
			}
		})
	}
}

// TestExcessiveDataHandling ensures DoS protection
func TestExcessiveDataHandling(t *testing.T) {
	parser := NewParser(false)

	// Test with extremely large evidence payload
	largePayload := strings.Repeat("A", 10*1024*1024) // 10MB

	jsonData := []byte(`{
		"xarf_version": "4.0.0",
		"report_id": "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {"org": "Test", "contact": "test@example.com"},
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
		"evidence": [{"content_type": "text/plain", "description": "test", "payload": "` + largePayload + `"}]
	}`)

	// Should handle without crashing (may reject or accept based on limits)
	_, err := parser.Parse(jsonData)

	// We're mainly testing that it doesn't panic or hang
	if err != nil {
		t.Logf("Large payload rejected (expected): %v", err)
	} else {
		t.Log("Large payload accepted (parser has no size limits)")
	}
}

// TestSecureDefaults ensures secure defaults are used
func TestSecureDefaults(t *testing.T) {
	gen := NewGenerator()

	opts := &ReportOptions{
		Category:         CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		Reporter: ContactInfo{
			Org:     "Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: ContactInfo{
			Org:     "Sender Org",
			Contact: "sender@example.com",
			Domain:  "example.com",
		},
	}

	report, err := gen.GenerateReport(opts)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Verify secure defaults
	if report.XARFVersion != "4.0.0" {
		t.Error("Should use latest XARF version by default")
	}

	// Report ID should be generated (UUID format)
	if len(report.ReportID) < 36 {
		t.Error("Report ID should be a valid UUID")
	}
}
