package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xarf/xarf-go"
)

// TestV4SampleFiles tests parsing of actual XARF v4 sample files
func TestV4SampleFiles(t *testing.T) {
	// Path to xarf-spec samples (relative to xarf-go directory)
	samplesDir := filepath.Join("..", "xarf-spec", "samples", "v4")

	// Check if samples directory exists
	if _, err := os.Stat(samplesDir); os.IsNotExist(err) {
		t.Skip("XARF spec samples not found, skipping integration tests")
		return
	}

	testCases := []struct {
		filename        string
		expectedCat     xarf.Category
		expectedType    string
		skipIfNotExists bool
	}{
		{
			filename:     "messaging-spam.json",
			expectedCat:  xarf.CategoryMessaging,
			expectedType: "spam",
		},
		{
			filename:     "connection-login-attack.json",
			expectedCat:  xarf.CategoryConnection,
			expectedType: "login_attack",
		},
		{
			filename:     "content-phishing.json",
			expectedCat:  xarf.CategoryContent,
			expectedType: "phishing",
		},
		{
			filename:     "infrastructure-botnet.json",
			expectedCat:  xarf.CategoryInfrastructure,
			expectedType: "botnet",
		},
		{
			filename:     "vulnerability-cve.json",
			expectedCat:  xarf.CategoryVulnerability,
			expectedType: "cve",
		},
		{
			filename:     "copyright-copyright.json",
			expectedCat:  xarf.CategoryCopyright,
			expectedType: "copyright",
		},
		{
			filename:     "reputation-blocklist.json",
			expectedCat:  xarf.CategoryReputation,
			expectedType: "blocklist",
		},
	}

	parser := xarf.NewParser(false)

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			filePath := filepath.Join(samplesDir, tc.filename)

			// Check if file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				if tc.skipIfNotExists {
					t.Skipf("Sample file %s not found, skipping", tc.filename)
					return
				}
				t.Fatalf("Sample file %s not found at %s", tc.filename, filePath)
			}

			// Read sample file
			data, err := os.ReadFile(filePath)
			require.NoError(t, err, "Failed to read sample file %s", tc.filename)

			// Parse the report
			report, err := parser.Parse(data)
			require.NoError(t, err, "Failed to parse %s", tc.filename)
			require.NotNil(t, report, "Parsed report should not be nil")

			// Verify category based on report type
			switch r := report.(type) {
			case *xarf.MessagingReport:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			case *xarf.ConnectionReport:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			case *xarf.ContentReport:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			case *xarf.InfrastructureReport:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			case *xarf.VulnerabilityReport:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			case *xarf.CopyrightReport:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			case *xarf.ReputationReport:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			case *xarf.Report:
				assert.Equal(t, tc.expectedCat, r.Category, "Category mismatch for %s", tc.filename)
				assert.Equal(t, tc.expectedType, r.Type, "Type mismatch for %s", tc.filename)
			default:
				t.Fatalf("Unexpected report type for %s: %T", tc.filename, report)
			}

			// Validate the parsed report
			validator := xarf.NewValidator()
			valid, errors := validator.ValidateReport(report)
			if !valid {
				t.Logf("Validation errors for %s:", tc.filename)
				for _, e := range errors {
					t.Logf("  - %s", e)
				}
			}
			assert.True(t, valid, "Report %s should be valid", tc.filename)
		})
	}
}

// TestCategoryField tests that only "category" field is accepted (not "class")
func TestCategoryField(t *testing.T) {
	testCases := []struct {
		name        string
		json        string
		expected    xarf.Category
		expectError bool
	}{
		{
			name: "Using category field (v4 spec)",
			json: `{
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
				"source_identifier": "192.0.2.1",
				"category": "messaging",
				"type": "spam",
				"evidence_source": "spamtrap"
			}`,
			expected:    xarf.CategoryMessaging,
			expectError: false,
		},
		{
			name: "Using class field (should fail - no longer supported)",
			json: `{
				"xarf_version": "4.0.0",
				"report_id": "test-456",
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
				"source_identifier": "192.0.2.1",
				"class": "connection",
				"type": "ddos",
				"evidence_source": "honeypot",
				"destination_ip": "203.0.113.1",
				"protocol": "tcp"
			}`,
			expectError: true,
		},
	}

	parser := xarf.NewParser(false)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := parser.ParseString(tc.json)

			if tc.expectError {
				require.Error(t, err, "Should fail when using 'class' field")
				return
			}

			require.NoError(t, err)
			require.NotNil(t, report)

			// Extract category from report
			var category xarf.Category
			switch r := report.(type) {
			case *xarf.MessagingReport:
				category = r.Category
			case *xarf.ConnectionReport:
				category = r.Category
			case *xarf.ContentReport:
				category = r.Category
			case *xarf.Report:
				category = r.Category
			}

			assert.Equal(t, tc.expected, category, "Category should match expected value")
		})
	}
}
