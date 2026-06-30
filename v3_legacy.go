package xarf

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// This file mirrors the JavaScript library's v3-legacy module: detection,
// conversion, and the deprecation warning all match the JS semantics (which
// differ from the older byte-oriented helpers in v3_compat.go).

// v3TypeMapping maps a XARF v3 ReportType to a v4 category and type.
//
// The base set mirrors V3_TYPE_MAPPING in the JavaScript library (hyphenated
// spellings such as "Login-Attack"). Deployed XARF v3 traffic, however, uses
// the CamelCase spellings defined by the v3 schema ("DOS", "PortScan",
// "LoginAttack"); those are added as aliases so real reports convert.
//
// Several other schema-defined ReportTypes (ChildAbuse, Trademark, Exploit,
// OpenService, WebCrawler, PotentiallyCompromisedAccount, Harassment) are
// intentionally NOT mapped here: they either have no v4.2.0 type, or their v4
// type requires fields the converter cannot populate from v3 data. They surface
// as a clear "unknown ReportType" error rather than producing an invalid v4 doc.
var v3TypeMapping = map[string]struct {
	Category Category
	Type     string
}{
	"Spam":         {CategoryMessaging, "spam"},
	"spam":         {CategoryMessaging, "spam"},
	"Login-Attack": {CategoryConnection, "login_attack"},
	"login-attack": {CategoryConnection, "login_attack"},
	"LoginAttack":  {CategoryConnection, "login_attack"}, // v3 schema spelling
	"Port-Scan":    {CategoryConnection, "port_scan"},
	"port-scan":    {CategoryConnection, "port_scan"},
	"PortScan":     {CategoryConnection, "port_scan"}, // v3 schema spelling
	"DDoS":         {CategoryConnection, "ddos"},
	"ddos":         {CategoryConnection, "ddos"},
	"DOS":          {CategoryConnection, "ddos"}, // v3 schema spelling
	"Phishing":     {CategoryContent, "phishing"},
	"phishing":     {CategoryContent, "phishing"},
	"Malware":      {CategoryContent, "malware"},
	"malware":      {CategoryContent, "malware"},
	"Botnet":       {CategoryInfrastructure, "botnet"},
	"botnet":       {CategoryInfrastructure, "botnet"},
	"Copyright":    {CategoryCopyright, "copyright"},
	"copyright":    {CategoryCopyright, "copyright"},
}

// GetV3DeprecationWarning returns the v3 deprecation warning message.
// Mirrors getV3DeprecationWarning() in the JavaScript library.
func GetV3DeprecationWarning() string {
	return strings.Join([]string{
		"DEPRECATION WARNING: XARF v3 format detected.",
		"The v3 format has been automatically converted to v4.",
		"Please update your systems to generate v4 reports directly.",
		"v3 support will be removed in a future major version.",
	}, " ")
}

// IsXARFv3 reports whether a decoded JSON object is a XARF v3 report.
// Mirrors isXARFv3() in the JavaScript library.
func IsXARFv3(data map[string]interface{}) bool {
	version, ok := data["Version"].(string)
	if !ok {
		return false
	}
	if version != "3" && version != "3.0" && version != "3.0.0" {
		return false
	}
	_, hasReporterInfo := data["ReporterInfo"]
	_, hasReport := data["Report"]
	return hasReporterInfo && hasReport
}

// ConvertV3toV4 converts a decoded XARF v3 object to a v4 object, appending any
// conversion warnings to warnings (if non-nil). Mirrors convertV3toV4() in the
// JavaScript library, including its error conditions.
func ConvertV3toV4(v3 map[string]interface{}, warnings *[]string) (map[string]interface{}, error) {
	report, _ := v3["Report"].(map[string]interface{})
	if report == nil {
		return nil, NewParseError("cannot convert v3 report: missing Report section", nil)
	}

	reportType, _ := report["ReportType"].(string)
	mapping, ok := v3TypeMapping[reportType]
	if !ok {
		return nil, NewParseError(fmt.Sprintf(
			"cannot convert v3 report: unknown ReportType '%s'. Supported types: %s",
			reportType, strings.Join(sortedV3Types(), ", ")), nil)
	}

	reporterInfo, _ := v3["ReporterInfo"].(map[string]interface{})

	sourceIdentifier, err := extractV3SourceIdentifier(report)
	if err != nil {
		return nil, err
	}

	contact, err := extractV3ContactInfo(reporterInfo, warnings)
	if err != nil {
		return nil, err
	}

	v4 := map[string]interface{}{
		"xarf_version":      SpecVersion,
		"report_id":         generateSimpleUUID(),
		"timestamp":         report["Date"],
		"reporter":          contact,
		"sender":            contact,
		"source_identifier": sourceIdentifier,
		"category":          string(mapping.Category),
		"type":              mapping.Type,
		"legacy_version":    "3",
		"_internal": map[string]interface{}{
			"original_report_type": reportType,
			"converted_at":         time.Now().UTC().Format(time.RFC3339),
		},
	}
	// description comes from the schema's free-text field ReporterNotes; the older
	// AttackDescription (non-schema) is kept as a fallback for other v3 dialects.
	if desc := stringOr(report["ReporterNotes"], stringOr(report["AttackDescription"], "")); desc != "" {
		v4["description"] = desc
	}
	if ev := convertV3Evidence(report, warnings); ev != nil {
		v4["evidence"] = ev
	}

	// evidence_source only when explicitly provided (AdditionalInfo.DetectionMethod).
	if ai, ok := report["AdditionalInfo"].(map[string]interface{}); ok {
		if dm, ok := ai["DetectionMethod"].(string); ok && dm != "" {
			v4["evidence_source"] = dm
		}
	}

	if err := addV3CategoryFields(v4, mapping.Category, report, warnings); err != nil {
		return nil, err
	}
	return v4, nil
}

func sortedV3Types() []string {
	keys := make([]string, 0, len(v3TypeMapping))
	for k := range v3TypeMapping {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extractV3SourceIdentifier mirrors extractSourceIdentifier().
func extractV3SourceIdentifier(report map[string]interface{}) (string, error) {
	if src, ok := report["Source"].(map[string]interface{}); ok {
		if ip, ok := src["IP"].(string); ok && ip != "" {
			return ip, nil
		}
	}
	if ip, ok := report["SourceIp"].(string); ok && ip != "" {
		return ip, nil
	}
	if src, ok := report["Source"].(map[string]interface{}); ok {
		if u, ok := src["URL"].(string); ok && u != "" {
			return u, nil
		}
	}
	if u, ok := report["Url"].(string); ok && u != "" {
		return u, nil
	}
	// SourceUrl is the schema-canonical URL field for content-class v3 reports
	// (e.g. Phishing/Malware), which carry no IP.
	if u, ok := report["SourceUrl"].(string); ok && u != "" {
		return u, nil
	}
	return "", NewParseError(
		"cannot convert v3 report: no source identifier found (expected Source.IP, SourceIp, Source.URL, Url, or SourceUrl)", nil)
}

// extractV3ContactInfo mirrors extractContactInfo().
func extractV3ContactInfo(reporterInfo map[string]interface{}, warnings *[]string) (map[string]interface{}, error) {
	if reporterInfo == nil {
		return nil, NewParseError(
			"cannot convert v3 report: missing reporter email (ReporterContactEmail and ReporterOrgEmail are both absent)", nil)
	}
	contact, _ := reporterInfo["ReporterContactEmail"].(string)
	if contact == "" {
		contact, _ = reporterInfo["ReporterOrgEmail"].(string)
	}
	if contact == "" {
		return nil, NewParseError(
			"cannot convert v3 report: missing reporter email (ReporterContactEmail and ReporterOrgEmail are both absent)", nil)
	}
	parts := strings.SplitN(contact, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, NewParseError(fmt.Sprintf(
			"cannot convert v3 report: reporter email '%s' is not a valid email address", contact), nil)
	}
	org, _ := reporterInfo["ReporterOrg"].(string)
	if org == "" {
		appendWarning(warnings, `No ReporterOrg found in v3 report, using "Unknown Organization"`)
		org = "Unknown Organization"
	}
	return map[string]interface{}{"org": org, "contact": contact, "domain": parts[1]}, nil
}

// convertV3Evidence converts v3 evidence samples to v4 evidence items. The
// schema-canonical source is the Report.Samples array, whose items carry
// Payload (+ Base64Encoded) and ContentType; Attachment/Data are accepted as
// fallbacks for other v3 dialects. v4 evidence_item.payload is always
// base64-encoded, with hash and size computed over the decoded bytes.
func convertV3Evidence(report map[string]interface{}, warnings *[]string) []interface{} {
	raw, ok := report["Samples"].([]interface{})
	if !ok || len(raw) == 0 {
		raw, ok = report["Attachment"].([]interface{})
		if !ok || len(raw) == 0 {
			return nil
		}
	}

	out := make([]interface{}, 0, len(raw))
	for _, item := range raw {
		att, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		payloadStr, _ := att["Payload"].(string)
		if payloadStr == "" {
			payloadStr, _ = att["Data"].(string) // non-schema dialect fallback
		}

		// Resolve the raw evidence bytes: when the v3 sample is already base64,
		// decode it; otherwise the payload is literal text. v4 always stores base64.
		var rawBytes []byte
		var v4Payload string
		if b64, _ := att["Base64Encoded"].(bool); b64 {
			rawBytes, _ = base64.StdEncoding.DecodeString(payloadStr)
			v4Payload = payloadStr
		} else {
			rawBytes = []byte(payloadStr)
			v4Payload = base64.StdEncoding.EncodeToString(rawBytes)
		}
		sum := sha256.Sum256(rawBytes)

		contentType, _ := att["ContentType"].(string)
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		ev := map[string]interface{}{
			"content_type": contentType,
			"payload":      v4Payload,
			"hash":         "sha256:" + hex.EncodeToString(sum[:]),
			"size":         len(rawBytes),
		}
		if desc, ok := att["Description"].(string); ok && desc != "" {
			ev["description"] = desc
		} else {
			appendWarning(warnings, "Evidence sample has no description, omitting field")
		}
		out = append(out, ev)
	}
	return out
}

// addV3CategoryFields mirrors addCategorySpecificFields().
func addV3CategoryFields(v4 map[string]interface{}, category Category, report map[string]interface{}, warnings *[]string) error {
	switch category {
	case CategoryMessaging:
		return addV3MessagingFields(v4, report, warnings)
	case CategoryConnection:
		return addV3ConnectionFields(v4, report, warnings)
	case CategoryContent:
		return addV3ContentFields(v4, report)
	case CategoryCopyright:
		return addV3CopyrightFields(v4, report)
	}
	return nil
}

func addV3CopyrightFields(v4, report map[string]interface{}) error {
	// v4 copyright/copyright requires infringing_url; v3 carries it as SourceUrl.
	url := stringOr(report["SourceUrl"], stringOr(report["Url"], ""))
	if url == "" {
		return NewParseError(
			"cannot convert v3 report: missing SourceUrl for copyright type. Copyright reports require an infringing URL", nil)
	}
	v4["infringing_url"] = url
	if wt := stringOr(report["InfringedMaterial"], ""); wt != "" {
		v4["work_title"] = wt
	}
	return nil
}

func addV3MessagingFields(v4, report map[string]interface{}, warnings *[]string) error {
	protocol := stringOr(report["Protocol"], additionalInfoString(report, "Protocol"))
	if protocol == "" {
		// XARF v3 messaging reports carry no Protocol field; v4 messaging types
		// require one. Default to smtp (the only messaging transport v3 modeled).
		protocol = "smtp"
		appendWarning(warnings, `No Protocol in v3 messaging report, defaulting to "smtp"`)
	}
	v4["protocol"] = protocol
	if from := stringOr(report["SmtpMailFromAddress"], additionalInfoString(report, "SMTPFrom")); from != "" {
		v4["smtp_from"] = from
	}
	if to, ok := report["SmtpRcptToAddress"].(string); ok && to != "" {
		v4["smtp_to"] = to
	}
	if subject := stringOr(report["SmtpMessageSubject"], additionalInfoString(report, "Subject")); subject != "" {
		v4["subject"] = subject
	}
	if port := v3SourcePort(report); port != nil {
		v4["source_port"] = *port
	}
	return nil
}

func addV3ConnectionFields(v4, report map[string]interface{}, warnings *[]string) error {
	protocol, _ := report["Protocol"].(string)
	if protocol == "" {
		// XARF v3 connection reports carry no Protocol field; v4 connection types
		// require one. Default to tcp (the common transport for scan/login/ddos).
		protocol = "tcp"
		appendWarning(warnings, `No Protocol in v3 connection report, defaulting to "tcp"`)
	}
	if dst, ok := report["DestinationIp"].(string); ok && dst != "" {
		v4["destination_ip"] = dst
	}
	v4["protocol"] = protocol
	if port := v3SourcePort(report); port != nil {
		v4["source_port"] = *port
	}
	if dp, ok := numberValue(report["DestinationPort"]); ok {
		v4["destination_port"] = dp
	}
	// Prefer the schema's FirstSeen; fall back to the report Date.
	if fs := stringOr(report["FirstSeen"], ""); fs != "" {
		v4["first_seen"] = fs
	} else {
		v4["first_seen"] = report["Date"]
	}
	if ac, ok := numberValue(report["AttackCount"]); ok {
		v4["attack_count"] = ac
	}
	return nil
}

func addV3ContentFields(v4, report map[string]interface{}) error {
	// SourceUrl is the schema-canonical field; Url/AdditionalInfo.URL/Source.URL
	// are accepted as fallbacks for other v3 dialects.
	url := stringOr(report["SourceUrl"], stringOr(report["Url"], additionalInfoString(report, "URL")))
	if url == "" {
		if src, ok := report["Source"].(map[string]interface{}); ok {
			url, _ = src["URL"].(string)
		}
	}
	if url == "" {
		return NewParseError(fmt.Sprintf(
			"cannot convert v3 report: missing URL for content type '%v'. Content reports require a URL field", v4["type"]), nil)
	}
	v4["url"] = url
	return nil
}

// --- small helpers ---

func appendWarning(warnings *[]string, msg string) {
	if warnings != nil {
		*warnings = append(*warnings, msg)
	}
}

func stringOr(primary interface{}, fallback string) string {
	if s, ok := primary.(string); ok && s != "" {
		return s
	}
	return fallback
}

func additionalInfoString(report map[string]interface{}, key string) string {
	if ai, ok := report["AdditionalInfo"].(map[string]interface{}); ok {
		if s, ok := ai[key].(string); ok {
			return s
		}
	}
	return ""
}

func v3SourcePort(report map[string]interface{}) *int {
	if src, ok := report["Source"].(map[string]interface{}); ok {
		if p, ok := numberValue(src["Port"]); ok {
			return &p
		}
	}
	if p, ok := numberValue(report["SourcePort"]); ok {
		return &p
	}
	return nil
}

// numberValue coerces a JSON number (float64) or int to int.
func numberValue(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}
