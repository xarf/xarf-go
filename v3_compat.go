package xarf

import (
	"encoding/json"
	"strings"
	"time"
)

// V3ReporterInfo represents XARF v3 reporter information structure
type V3ReporterInfo struct {
	ReporterOrg       string `json:"ReporterOrg"`
	ReporterOrgDomain string `json:"ReporterOrgDomain"`
	ReporterOrgEmail  string `json:"ReporterOrgEmail"`
}

// V3ReportData represents XARF v3 report data structure
type V3ReportData struct {
	ReportClass      string                 `json:"ReportClass"`
	ReportType       string                 `json:"ReportType"`
	SourceIP         string                 `json:"SourceIP"`
	Date             string                 `json:"Date"`
	EvidenceSource   string                 `json:"EvidenceSource"`
	Description      string                 `json:"Description,omitempty"`
	AdditionalFields map[string]interface{} `json:"-"`
}

// V3Report represents a complete XARF v3 report
type V3Report struct {
	Version      string         `json:"Version"`
	ReporterInfo V3ReporterInfo `json:"ReporterInfo"`
	Report       V3ReportData   `json:"Report"`
	rawData      map[string]interface{}
}

// IsV3Report detects if JSON data contains a XARF v3 format report
func IsV3Report(data []byte) bool {
	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return false
	}

	// V3 reports have "Version" field (capital V)
	if version, ok := rawData["Version"].(string); ok {
		// Check if it starts with "3."
		return strings.HasPrefix(version, "3.")
	}

	return false
}

// ConvertV3ToV4 converts a XARF v3 format report to v4 format
func ConvertV3ToV4(data []byte) ([]byte, error) {
	var v3Report V3Report
	if err := json.Unmarshal(data, &v3Report); err != nil {
		return nil, NewParseError("failed to parse v3 report", err)
	}

	// Also unmarshal into raw map to preserve additional fields
	if err := json.Unmarshal(data, &v3Report.rawData); err != nil {
		return nil, NewParseError("failed to parse v3 report raw data", err)
	}

	// Extract additional fields from Report section
	if reportData, ok := v3Report.rawData["Report"].(map[string]interface{}); ok {
		v3Report.Report.AdditionalFields = make(map[string]interface{})
		// Copy all fields except the known v3 fields
		knownFields := map[string]bool{
			"ReportClass":    true,
			"ReportType":     true,
			"SourceIP":       true,
			"Date":           true,
			"EvidenceSource": true,
			"Description":    true,
		}
		for key, value := range reportData {
			if !knownFields[key] {
				v3Report.Report.AdditionalFields[key] = value
			}
		}
	}

	// Convert ReportClass to lowercase category
	// Handle special case: v3 "Abuse" maps to v4 "connection"
	category := GetV4Category(v3Report.Report.ReportClass)

	// Parse timestamp
	var timestamp time.Time
	if v3Report.Report.Date != "" {
		var err error
		// Try RFC3339 format first
		timestamp, err = time.Parse(time.RFC3339, v3Report.Report.Date)
		if err != nil {
			// Try other common formats
			timestamp, err = time.Parse("2006-01-02T15:04:05Z07:00", v3Report.Report.Date)
			if err != nil {
				timestamp = time.Now().UTC()
			}
		}
	} else {
		timestamp = time.Now().UTC()
	}

	// Map v3 evidence source to v4
	evidenceSource := mapV3EvidenceSource(v3Report.Report.EvidenceSource)

	// Build v4 report structure
	v4Report := map[string]interface{}{
		"xarf_version":      XARFVersion,
		"report_id":         generateSimpleUUID(),
		"timestamp":         timestamp.Format(time.RFC3339),
		"source_identifier": v3Report.Report.SourceIP,
		"category":          category,
		"type":              v3Report.Report.ReportType,
		"evidence_source":   evidenceSource,
		"reporter": map[string]interface{}{
			"org":     v3Report.ReporterInfo.ReporterOrg,
			"contact": v3Report.ReporterInfo.ReporterOrgEmail,
			"domain":  v3Report.ReporterInfo.ReporterOrgDomain,
		},
		"sender": map[string]interface{}{
			"org":     v3Report.ReporterInfo.ReporterOrg,
			"contact": v3Report.ReporterInfo.ReporterOrgEmail,
			"domain":  v3Report.ReporterInfo.ReporterOrgDomain,
		},
	}

	// Add description if present
	if v3Report.Report.Description != "" {
		v4Report["description"] = v3Report.Report.Description
	}

	// Add additional fields from v3 report
	for key, value := range v3Report.Report.AdditionalFields {
		// Convert key to snake_case if needed
		v4Key := toSnakeCase(key)
		v4Report[v4Key] = value
	}

	// Convert to JSON
	return json.Marshal(v4Report)
}

// mapV3EvidenceSource maps v3 evidence source values to v4
func mapV3EvidenceSource(v3Source string) string {
	mapping := map[string]string{
		"spamtrap":            "spamtrap",
		"honeypot":            "honeypot",
		"user_report":         "user_report",
		"automated_scan":      "automated_scan",
		"manual_analysis":     "manual_analysis",
		"vulnerability_scan":  "vulnerability_scan",
		"researcher_analysis": "researcher_analysis",
		"threat_intelligence": "threat_intelligence",
		"flow_analysis":       "flow_analysis",
		"ids_ips":             "ids_ips",
		"siem":                "siem",
	}

	if mapped, ok := mapping[v3Source]; ok {
		return mapped
	}

	// Default to automated_scan if unknown
	return "automated_scan"
}

// toSnakeCase converts a string to snake_case
func toSnakeCase(s string) string {
	// Handle common field name mappings first
	mapping := map[string]string{
		"SMTPFrom":        "smtp_from",
		"SMTPTo":          "smtp_to",
		"Subject":         "subject",
		"MessageID":       "message_id",
		"DestinationIP":   "destination_ip",
		"DestinationPort": "destination_port",
		"Protocol":        "protocol",
		"URL":             "url",
		"ContentType":     "content_type",
	}

	if mapped, ok := mapping[s]; ok {
		return mapped
	}

	// Generic conversion for other fields
	result := make([]rune, 0, len(s)+5) // Pre-allocate with buffer for underscores
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result = append(result, '_')
		}
		result = append(result, r)
	}
	return strings.ToLower(string(result))
}

// generateSimpleUUID generates a simple UUID for v3 conversion
func generateSimpleUUID() string {
	g := NewGenerator()
	return g.GenerateUUID()
}

// GetCategory is a helper method to extract category from any report type
func (r *Report) GetCategory() string {
	return string(r.Category)
}

// ParseV3Report parses a XARF v3 report and returns it as v4
func ParseV3Report(data []byte) (interface{}, error) {
	// Convert v3 to v4
	v4Data, err := ConvertV3ToV4(data)
	if err != nil {
		return nil, err
	}

	// Parse as v4
	parser := NewParser(false)
	return parser.Parse(v4Data)
}

// V3CategoryMapping maps v3 category names to v4 category names
var V3CategoryMapping = map[string]string{
	"Abuse":          "connection", // v3 "Abuse" maps to v4 "connection"
	"Messaging":      "messaging",
	"Connection":     "connection",
	"Content":        "content",
	"Copyright":      "copyright",
	"Infrastructure": "infrastructure",
	"Vulnerability":  "vulnerability",
	"Reputation":     "reputation",
}

// GetV4Category returns the v4 category name for a v3 category
func GetV4Category(v3Category string) string {
	if v4Category, ok := V3CategoryMapping[v3Category]; ok {
		return v4Category
	}
	// Default to lowercase version
	return strings.ToLower(v3Category)
}
