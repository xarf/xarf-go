package xarf

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validMessagingJSON is a complete, schema-valid messaging/spam report.
const validMessagingJSON = `{
	"xarf_version": "4.2.0",
	"report_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	"timestamp": "2024-01-15T10:30:00Z",
	"source_identifier": "192.0.2.100",
	"source_port": 25,
	"category": "messaging",
	"type": "spam",
	"protocol": "smtp",
	"smtp_from": "spammer@example.com",
	"evidence_source": "spamtrap",
	"reporter": {"org": "T", "contact": "t@example.com", "domain": "example.com"},
	"sender": {"org": "S", "contact": "s@example.com", "domain": "example.com"}
}`

func TestVersionExports(t *testing.T) {
	assert.Equal(t, "4.2.0", SpecVersion)
	assert.Equal(t, "4.2.0", XARFVersion)
	assert.Equal(t, "v4.2.0", BundledSpecVersion)
	assert.NotEmpty(t, Version)
}

func TestParseValidReport(t *testing.T) {
	result, err := Parse([]byte(validMessagingJSON), nil)
	require.NoError(t, err)
	assert.Empty(t, result.Errors, "valid report should have no errors")
	assert.Empty(t, result.Warnings)
	assert.Equal(t, "messaging", result.Report["category"])
}

func TestParseInvalidJSONReturnsError(t *testing.T) {
	_, err := Parse([]byte(`{not json`), nil)
	require.Error(t, err)
	var parseErr *ParseError
	assert.ErrorAs(t, err, &parseErr)
}

func TestParseReportsValidationErrorsNotAsError(t *testing.T) {
	// Minimal messaging/spam is missing type-required fields; Parse must return
	// these in Errors rather than failing.
	minimal := `{
		"xarf_version": "4.2.0",
		"report_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"timestamp": "2024-01-15T10:30:00Z",
		"source_identifier": "192.0.2.100",
		"category": "messaging",
		"type": "spam",
		"reporter": {"org": "T", "contact": "t@example.com", "domain": "example.com"},
		"sender": {"org": "S", "contact": "s@example.com", "domain": "example.com"}
	}`
	result, err := Parse([]byte(minimal), nil)
	require.NoError(t, err)
	require.NotEmpty(t, result.Errors)
	joined := strings.Join(result.Errors, " ")
	for _, field := range []string{"protocol", "smtp_from", "source_port"} {
		assert.Contains(t, joined, field, "expected %s to be flagged", field)
	}
}

func TestParseUnknownFieldWarning(t *testing.T) {
	withUnknown := strings.Replace(validMessagingJSON,
		`"protocol": "smtp",`,
		`"protocol": "smtp", "bogus_field": 1,`, 1)
	result, err := Parse([]byte(withUnknown), nil)
	require.NoError(t, err)
	require.Len(t, result.Warnings, 1)
	assert.Contains(t, result.Warnings[0], "bogus_field")
	assert.Contains(t, result.Warnings[0], "Unknown field")
}

func TestParseStrictPromotesWarningsAndRecommended(t *testing.T) {
	// A valid report still fails strict mode because x-recommended fields are
	// promoted to required.
	result, err := Parse([]byte(validMessagingJSON), &ParseOptions{Strict: true})
	require.NoError(t, err)
	assert.NotEmpty(t, result.Errors)
	assert.Empty(t, result.Warnings, "strict mode folds warnings into errors")
}

func TestParseShowMissingOptional(t *testing.T) {
	result, err := Parse([]byte(validMessagingJSON), &ParseOptions{ShowMissingOptional: true})
	require.NoError(t, err)
	require.NotEmpty(t, result.Info)
	for _, info := range result.Info {
		assert.True(t,
			strings.HasPrefix(info.Message, "OPTIONAL:") || strings.HasPrefix(info.Message, "RECOMMENDED:"),
			"unexpected info prefix: %s", info.Message)
	}

	// Without the option, Info is empty.
	plain, _ := Parse([]byte(validMessagingJSON), nil)
	assert.Empty(t, plain.Info)
}

func TestParseMaxInputBytes(t *testing.T) {
	_, err := Parse([]byte(validMessagingJSON), &ParseOptions{MaxInputBytes: 10})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maxInputBytes")

	// Within the limit parses fine.
	_, err = Parse([]byte(validMessagingJSON), &ParseOptions{MaxInputBytes: len(validMessagingJSON) + 1})
	require.NoError(t, err)

	// Zero means no limit.
	_, err = Parse([]byte(validMessagingJSON), &ParseOptions{MaxInputBytes: 0})
	require.NoError(t, err)
}

func TestCreateReportAutoFillsMetadata(t *testing.T) {
	result := CreateReport(map[string]interface{}{
		"category":          "messaging",
		"type":              "spam",
		"source_identifier": "192.0.2.100",
		"source_port":       float64(25),
		"protocol":          "smtp",
		"smtp_from":         "spammer@example.com",
		"evidence_source":   "spamtrap",
		"reporter":          map[string]interface{}{"org": "T", "contact": "t@example.com", "domain": "example.com"},
		"sender":            map[string]interface{}{"org": "S", "contact": "s@example.com", "domain": "example.com"},
	}, nil)

	assert.Equal(t, "4.2.0", result.Report["xarf_version"])
	assert.NotEmpty(t, result.Report["report_id"])
	assert.NotEmpty(t, result.Report["timestamp"])
	assert.Empty(t, result.Errors, "errors: %v", result.Errors)
}

func TestCreateReportRespectsProvidedIDAndTimestamp(t *testing.T) {
	result := CreateReport(map[string]interface{}{
		"report_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"timestamp": "2024-01-15T10:30:00Z",
		"category":  "messaging",
		"type":      "spam",
	}, nil)
	assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", result.Report["report_id"])
	assert.Equal(t, "2024-01-15T10:30:00Z", result.Report["timestamp"])
}

func TestCreateEvidence(t *testing.T) {
	payload := []byte("hello world")

	ev := CreateEvidence("message/rfc822", payload, &EvidenceOptions{Description: "spam email"})
	assert.Equal(t, "message/rfc822", ev.ContentType)
	assert.Equal(t, "spam email", ev.Description)
	assert.Equal(t, base64.StdEncoding.EncodeToString(payload), ev.Payload)
	assert.Equal(t, len(payload), ev.Size)
	assert.True(t, strings.HasPrefix(ev.Hash, "sha256:"), "default hash should be sha256: prefixed, got %s", ev.Hash)

	for _, algo := range []string{"sha512", "sha1", "md5"} {
		ev := CreateEvidence("text/plain", payload, &EvidenceOptions{HashAlgorithm: algo})
		assert.True(t, strings.HasPrefix(ev.Hash, algo+":"), "hash should be %s: prefixed, got %s", algo, ev.Hash)
	}
}

func TestIsXARFv3(t *testing.T) {
	assert.True(t, IsXARFv3(map[string]interface{}{
		"Version": "3", "ReporterInfo": map[string]interface{}{}, "Report": map[string]interface{}{},
	}))
	assert.True(t, IsXARFv3(map[string]interface{}{
		"Version": "3.0.0", "ReporterInfo": map[string]interface{}{}, "Report": map[string]interface{}{},
	}))
	assert.False(t, IsXARFv3(map[string]interface{}{"Version": "4.2.0"}))
	assert.False(t, IsXARFv3(map[string]interface{}{"xarf_version": "4.2.0"}))
}

func TestConvertV3toV4(t *testing.T) {
	v3 := map[string]interface{}{
		"Version": "3",
		"ReporterInfo": map[string]interface{}{
			"ReporterOrg":       "Acme Security",
			"ReporterOrgEmail":  "abuse@acme.example",
			"ReporterOrgDomain": "acme.example",
		},
		"Report": map[string]interface{}{
			"ReportType":          "Spam",
			"Date":                "2024-01-15T10:30:00Z",
			"Source":              map[string]interface{}{"IP": "192.0.2.1", "Port": float64(25)},
			"SmtpMailFromAddress": "spammer@evil.example",
			"Protocol":            "smtp",
		},
	}

	var warnings []string
	v4, err := ConvertV3toV4(v3, &warnings)
	require.NoError(t, err)
	assert.Equal(t, "4.2.0", v4["xarf_version"])
	assert.Equal(t, "messaging", v4["category"])
	assert.Equal(t, "spam", v4["type"])
	assert.Equal(t, "192.0.2.1", v4["source_identifier"])
	assert.Equal(t, "smtp", v4["protocol"])
	assert.Equal(t, "spammer@evil.example", v4["smtp_from"])
	assert.Equal(t, 25, v4["source_port"])
	assert.Equal(t, "3", v4["legacy_version"])
	reporter := v4["reporter"].(map[string]interface{})
	assert.Equal(t, "acme.example", reporter["domain"])
}

func TestConvertV3toV4UnknownTypeErrors(t *testing.T) {
	_, err := ConvertV3toV4(map[string]interface{}{
		"Report": map[string]interface{}{"ReportType": "TotallyUnknown"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown ReportType")
}

func TestParseAutoConvertsV3(t *testing.T) {
	v3 := `{
		"Version": "3",
		"ReporterInfo": {"ReporterOrg": "Acme", "ReporterOrgEmail": "abuse@acme.example", "ReporterOrgDomain": "acme.example"},
		"Report": {"ReportType": "Spam", "Date": "2024-01-15T10:30:00Z", "Source": {"IP": "192.0.2.1", "Port": 25}, "SmtpMailFromAddress": "spammer@evil.example", "Protocol": "smtp"}
	}`
	result, err := Parse([]byte(v3), nil)
	require.NoError(t, err)
	assert.Equal(t, "messaging", result.Report["category"])
	assert.Equal(t, "3", result.Report["legacy_version"])
	require.NotEmpty(t, result.Warnings)
	assert.Contains(t, result.Warnings[0], "DEPRECATION WARNING")
}

func TestGetV3DeprecationWarning(t *testing.T) {
	assert.Contains(t, GetV3DeprecationWarning(), "DEPRECATION WARNING")
	assert.Contains(t, GetV3DeprecationWarning(), "v4")
}

func TestParseStringEquivalentToParse(t *testing.T) {
	r1, err1 := Parse([]byte(validMessagingJSON), nil)
	r2, err2 := ParseString(validMessagingJSON, nil)
	require.NoError(t, err1)
	require.NoError(t, err2)
	b1, _ := json.Marshal(r1.Report)
	b2, _ := json.Marshal(r2.Report)
	assert.JSONEq(t, string(b1), string(b2))
}
