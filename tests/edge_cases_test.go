package tests

import (
	"strings"
	"testing"

	"github.com/xarf/xarf-go"
)

// TestEmptyFields tests handling of empty/missing fields
func TestEmptyFields(t *testing.T) {
	tests := []struct {
		name    string
		jsonStr string
		wantErr bool
	}{
		{
			name: "Missing category",
			jsonStr: `{
				"xarf_version": "4.2.0",
				"report_id": "550e8400-e29b-41d4-a716-446655440000",
				"timestamp": "2024-01-15T10:30:00Z",
				"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
				"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
				"source_identifier": "192.0.2.100",
				"type": "spam"
			}`,
			wantErr: true,
		},
		{
			name: "Empty reporter org",
			jsonStr: `{
				"xarf_version": "4.2.0",
				"report_id": "550e8400-e29b-41d4-a716-446655440000",
				"timestamp": "2024-01-15T10:30:00Z",
				"reporter": {"org": "", "contact": "test@example.com", "domain": "example.com"},
				"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
				"source_identifier": "192.0.2.100",
				"category": "messaging",
				"type": "spam"
			}`,
			wantErr: false, // Empty org should be allowed during parsing
		},
		{
			name: "Missing timestamp",
			jsonStr: `{
				"xarf_version": "4.2.0",
				"report_id": "550e8400-e29b-41d4-a716-446655440000",
				"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
				"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
				"source_identifier": "192.0.2.100",
				"category": "messaging",
				"type": "spam"
			}`,
			wantErr: false, // Parser is lenient, validation should catch this
		},
		{
			name: "Missing report_id",
			jsonStr: `{
				"xarf_version": "4.2.0",
				"timestamp": "2024-01-15T10:30:00Z",
				"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
				"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
				"source_identifier": "192.0.2.100",
				"category": "messaging",
				"type": "spam"
			}`,
			wantErr: false, // Parser is lenient, validation should catch this
		},
	}

	parser := xarf.NewParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.Parse([]byte(tt.jsonStr))
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestUnicodeHandling tests Unicode character handling
func TestUnicodeHandling(t *testing.T) {
	parser := xarf.NewParser(false)

	jsonData := []byte(`{
		"xarf_version": "4.2.0",
		"report_id": "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {"org": "测试组织 🚀", "contact": "test@example.com", "domain": "example.com"},
		"sender": {"org": "Sender Org", "contact": "sender@example.com", "domain": "example.com"},
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
		"description": "Unicode test: ñ é ü 中文 العربية"
	}`)

	result, err := parser.Parse(jsonData)
	if err != nil {
		t.Fatalf("Failed to parse Unicode content: %v", err)
	}

	report, ok := result.(*xarf.MessagingReport)
	if !ok {
		t.Fatal("Expected MessagingReport type")
	}

	if report.Reporter.Org != "测试组织 🚀" {
		t.Errorf("Unicode org not preserved: got %s", report.Reporter.Org)
	}

	if !strings.Contains(report.Description, "中文") {
		t.Errorf("Unicode description not preserved: got %s", report.Description)
	}
}

// TestTimestampFormats tests various timestamp formats
func TestTimestampFormats(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		wantErr   bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", false},
		{"RFC3339 with TZ", "2024-01-15T10:30:00+01:00", false},
		{"RFC3339 with milliseconds", "2024-01-15T10:30:00.123Z", false},
		{"RFC3339 with microseconds", "2024-01-15T10:30:00.123456Z", false},
		{"Invalid format", "2024-01-15 10:30:00", true},
		{"Empty", "", true},
		{"Invalid date", "2024-13-45T10:30:00Z", true},
	}

	parser := xarf.NewParser(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData := []byte(`{
				"xarf_version": "4.2.0",
				"report_id": "550e8400-e29b-41d4-a716-446655440000",
				"timestamp": "` + tt.timestamp + `",
				"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
				"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
				"source_identifier": "192.0.2.100",
				"category": "messaging",
				"type": "spam"
			}`)

			_, err := parser.Parse(jsonData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() with timestamp %s: error = %v, wantErr %v", tt.timestamp, err, tt.wantErr)
			}
		})
	}
}

// TestLargeReports tests handling of reports with many evidence items
func TestLargeReports(t *testing.T) {
	parser := xarf.NewParser(false)

	// Build report with 100 evidence items
	jsonStart := `{
		"xarf_version": "4.2.0",
		"report_id": "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
		"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
		"evidence": [`

	var evidence strings.Builder
	for i := 0; i < 100; i++ {
		if i > 0 {
			evidence.WriteString(",")
		}
		evidence.WriteString(`{"content_type":"text/plain","description":"Evidence `)
		evidence.WriteString(string(rune('0' + i%10)))
		evidence.WriteString(`","payload":"data"}`)
	}

	jsonEnd := `]}`
	jsonData := jsonStart + evidence.String() + jsonEnd

	result, err := parser.Parse([]byte(jsonData))
	if err != nil {
		t.Fatalf("Failed to parse large report: %v", err)
	}

	report, ok := result.(*xarf.MessagingReport)
	if !ok {
		t.Fatal("Expected MessagingReport type")
	}

	if len(report.Evidence) != 100 {
		t.Errorf("Expected 100 evidence items, got %d", len(report.Evidence))
	}
}

// TestBoundaryValues tests boundary values for various fields
func TestBoundaryValues(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		wantErr bool
	}{
		{
			name:    "Empty description",
			field:   "description",
			value:   "",
			wantErr: false,
		},
		{
			name:    "Very long description",
			field:   "description",
			value:   strings.Repeat("a", 10000),
			wantErr: false,
		},
		{
			name:    "Maximum confidence",
			field:   "confidence",
			value:   "1.0",
			wantErr: false,
		},
		{
			name:    "Minimum confidence",
			field:   "confidence",
			value:   "0.0",
			wantErr: false,
		},
	}

	parser := xarf.NewParser(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jsonData string
			if tt.field == "confidence" {
				jsonData = `{
					"xarf_version": "4.2.0",
					"report_id": "550e8400-e29b-41d4-a716-446655440000",
					"timestamp": "2024-01-15T10:30:00Z",
					"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
					"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
					"source_identifier": "192.0.2.100",
					"category": "messaging",
					"type": "spam",
					"confidence": ` + tt.value + `
				}`
			} else {
				jsonData = `{
					"xarf_version": "4.2.0",
					"report_id": "550e8400-e29b-41d4-a716-446655440000",
					"timestamp": "2024-01-15T10:30:00Z",
					"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
					"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
					"source_identifier": "192.0.2.100",
					"category": "messaging",
					"type": "spam",
					"` + tt.field + `": "` + tt.value + `"
				}`
			}

			_, err := parser.Parse([]byte(jsonData))
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNullValues tests handling of null values in optional fields
func TestNullValues(t *testing.T) {
	parser := xarf.NewParser(false)

	jsonData := []byte(`{
		"xarf_version": "4.2.0",
		"report_id": "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {"org": "Test", "contact": "test@example.com", "domain": "example.com"},
		"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
		"description": null,
		"evidence": null,
		"severity": null,
		"confidence": null,
		"tags": null
	}`)

	result, err := parser.Parse(jsonData)
	if err != nil {
		t.Fatalf("Failed to parse report with null values: %v", err)
	}

	report, ok := result.(*xarf.MessagingReport)
	if !ok {
		t.Fatal("Expected MessagingReport type")
	}

	if report.Description != "" {
		t.Errorf("Expected empty description, got %s", report.Description)
	}

	if report.Evidence != nil {
		t.Errorf("Expected nil evidence, got %v", report.Evidence)
	}
}

// TestMalformedJSON tests handling of malformed JSON
func TestMalformedJSON(t *testing.T) {
	tests := []struct {
		name    string
		jsonStr string
	}{
		{"Missing closing brace", `{"xarf_version": "4.2.0"`},
		{"Invalid JSON syntax", `{xarf_version: "4.2.0"}`},
		{"Trailing comma", `{"xarf_version": "4.2.0",}`},
		{"Unquoted key", `{xarf_version: "4.2.0"}`},
		{"Empty JSON", ``},
		{"Only whitespace", `   `},
	}

	parser := xarf.NewParser(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.Parse([]byte(tt.jsonStr))
			if err == nil {
				t.Error("Expected error for malformed JSON, got nil")
			}
		})
	}
}

// TestSpecialCharacters tests handling of special characters
func TestSpecialCharacters(t *testing.T) {
	parser := xarf.NewParser(false)

	specialChars := []string{
		`\n\r\t`,
		`"quotes"`,
		`back\slash`,
		`forward/slash`,
		`null\x00byte`,
	}

	for _, chars := range specialChars {
		t.Run("Special chars: "+chars, func(t *testing.T) {
			jsonData := []byte(`{
				"xarf_version": "4.2.0",
				"report_id": "550e8400-e29b-41d4-a716-446655440000",
				"timestamp": "2024-01-15T10:30:00Z",
				"reporter": {"org": "Test` + chars + `", "contact": "test@example.com", "domain": "example.com"},
				"sender": {"org": "Sender", "contact": "sender@example.com", "domain": "example.com"},
				"source_identifier": "192.0.2.100",
				"category": "messaging",
				"type": "spam"
			}`)

			// Should either parse successfully or fail gracefully
			_, err := parser.Parse(jsonData)
			if err != nil {
				t.Logf("Special characters rejected (acceptable): %v", err)
			}
		})
	}
}
