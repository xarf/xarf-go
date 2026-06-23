package xarf

import (
	"encoding/json"
	"testing"
	"time"
)

// Sample data generators for benchmarks

// generateMessagingReportJSON creates a realistic messaging report JSON
func generateMessagingReportJSON() []byte {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"timestamp":    "2024-01-15T10:30:00Z",
		"reporter": map[string]interface{}{
			"org":     "Email Security Provider",
			"contact": "abuse@provider.example.com",
			"domain":  "provider.example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Compromised Organization",
			"contact": "security@victim.example.com",
			"domain":  "victim.example.com",
		},
		"source_identifier":   "192.0.2.100",
		"category":            "messaging",
		"type":                "spam",
		"evidence_source":     "spamtrap",
		"protocol":            "smtp",
		"smtp_from":           "spammer@malicious.example.com",
		"smtp_to":             "user@victim.example.com",
		"subject":             "You have won a prize! Click here to claim",
		"message_id":          "<abcd1234.1234567@malicious.example.com>",
		"sender_display_name": "Prize Delivery Service",
		"target_victim":       "user@victim.example.com",
		"message_content":     "Click here to claim your prize: http://malicious.example.com/claim?token=abc123",
		"description":         "Phishing email attempting to collect user credentials",
		"severity":            "high",
		"confidence":          0.95,
		"tags":                []string{"phishing", "spam", "urgent"},
	}
	data, _ := json.Marshal(reportData)
	return data
}

// generateConnectionReportJSON creates a realistic connection report JSON
func generateConnectionReportJSON() []byte {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "b2c3d4e5-f6g7-8901-bcde-f1234567890a",
		"timestamp":    "2024-01-15T11:00:00Z",
		"reporter": map[string]interface{}{
			"org":     "Network Security Team",
			"contact": "abuse@security.example.com",
			"domain":  "security.example.com",
		},
		"sender": map[string]interface{}{
			"org":     "ISP Operations",
			"contact": "noc@isp.example.com",
			"domain":  "isp.example.com",
		},
		"source_identifier": "192.0.2.200",
		"category":          "connection",
		"type":              "ddos",
		"evidence_source":   "honeypot",
		"destination_ip":    "203.0.113.10",
		"protocol":          "tcp",
		"destination_port":  80,
		"attack_type":       "syn_flood",
		"duration_minutes":  45,
		"packet_count":      int64(5000000),
		"byte_count":        int64(2500000000),
		"description":       "SYN flood attack on web server",
		"severity":          "critical",
		"confidence":        0.99,
		"tags":              []string{"ddos", "syn_flood", "critical"},
	}
	data, _ := json.Marshal(reportData)
	return data
}

// generateContentReportJSON creates a realistic content report JSON
func generateContentReportJSON() []byte {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "c3d4e5f6-g7h8-9012-cdef-234567890abc",
		"timestamp":    "2024-01-15T12:00:00Z",
		"reporter": map[string]interface{}{
			"org":     "Web Security Team",
			"contact": "report@websecurity.example.com",
			"domain":  "websecurity.example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Hosting Provider",
			"contact": "abuse@hosting.example.com",
			"domain":  "hosting.example.com",
		},
		"source_identifier":            "192.0.2.300",
		"category":                     "content",
		"type":                         "phishing_site",
		"evidence_source":              "user_report",
		"url":                          "http://phishing.compromised-site.example.com/fake-login",
		"content_type":                 "text/html",
		"attack_type":                  "phishing",
		"affected_pages":               []string{"/fake-login", "/credential-capture"},
		"cms_platform":                 "WordPress",
		"vulnerability_exploited":      "Unpatched Plugin",
		"affected_parameters":          []string{"username", "password"},
		"payload_detected":             "<script>alert('XSS')</script>",
		"data_exposed":                 []string{"usernames", "hashed_passwords"},
		"database_type":                "MySQL",
		"records_potentially_affected": 1500,
		"description":                  "Website compromised with phishing content",
		"severity":                     "high",
		"confidence":                   0.92,
		"tags":                         []string{"phishing", "web_compromise", "urgent"},
	}
	data, _ := json.Marshal(reportData)
	return data
}

// generateReportWithEvidence creates a report with multiple evidence items
func generateReportWithEvidence() []byte {
	reportData := map[string]interface{}{
		"xarf_version": "4.2.0",
		"report_id":    "d4e5f6g7-h8i9-0123-defg-345678901bcd",
		"timestamp":    "2024-01-15T13:00:00Z",
		"reporter": map[string]interface{}{
			"org":     "Incident Response Team",
			"contact": "ir@example.com",
			"domain":  "example.com",
		},
		"sender": map[string]interface{}{
			"org":     "Affected Organization",
			"contact": "security@affected.example.com",
			"domain":  "affected.example.com",
		},
		"source_identifier":  "192.0.2.400",
		"category":           "vulnerability",
		"type":               "unpatched_server",
		"evidence_source":    "automated_scan",
		"cve":                "CVE-2024-1234",
		"cvss":               9.8,
		"affected_software":  "Apache Web Server",
		"affected_version":   "2.4.56",
		"vulnerability_type": "Remote Code Execution",
		"exploit_available":  true,
		"patch_available":    true,
		"recommended_action": "Update to version 2.4.60 or later",
		"port":               8080,
		"service":            "apache",
		"description":        "Critical RCE vulnerability detected",
		"severity":           "critical",
		"confidence":         0.98,
		"evidence": []map[string]interface{}{
			{
				"content_type": "text/plain",
				"description":  "Vulnerability scan log",
				"payload":      "Vulnerability scan results showing CVE-2024-1234 detected on port 8080",
				"hash":         "abcd1234efgh5678ijkl90mn",
			},
			{
				"content_type": "application/json",
				"description":  "CVSS Vector",
				"payload":      `{"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}`,
				"hash":         "efgh5678ijkl90mnopqr1234",
			},
			{
				"content_type": "text/html",
				"description":  "Proof of concept HTML",
				"payload":      "<html><body>PoC code for vulnerability reproduction</body></html>",
				"hash":         "ijkl90mnopqr1234stuv5678",
			},
		},
		"tags": []string{"rce", "critical", "unpatched"},
	}
	data, _ := json.Marshal(reportData)
	return data
}

// BenchmarkParse benchmarks parsing a typical XARF report
func BenchmarkParse(b *testing.B) {
	reportJSON := generateMessagingReportJSON()
	parser := NewParser(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
	}
}

// BenchmarkParseMessaging benchmarks parsing messaging category reports
func BenchmarkParseMessaging(b *testing.B) {
	reportJSON := generateMessagingReportJSON()
	parser := NewParser(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
		if _, ok := result.(*MessagingReport); !ok {
			b.Fatalf("Expected MessagingReport, got %T", result)
		}
	}
}

// BenchmarkParseConnection benchmarks parsing connection category reports
func BenchmarkParseConnection(b *testing.B) {
	reportJSON := generateConnectionReportJSON()
	parser := NewParser(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
		if _, ok := result.(*ConnectionReport); !ok {
			b.Fatalf("Expected ConnectionReport, got %T", result)
		}
	}
}

// BenchmarkParseContent benchmarks parsing content category reports
func BenchmarkParseContent(b *testing.B) {
	reportJSON := generateContentReportJSON()
	parser := NewParser(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
		if _, ok := result.(*ContentReport); !ok {
			b.Fatalf("Expected ContentReport, got %T", result)
		}
	}
}

// BenchmarkParseWithEvidence benchmarks parsing reports with evidence items
func BenchmarkParseWithEvidence(b *testing.B) {
	reportJSON := generateReportWithEvidence()
	parser := NewParser(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
		if _, ok := result.(*VulnerabilityReport); !ok {
			b.Fatalf("Expected VulnerabilityReport, got %T", result)
		}
	}
}

// BenchmarkValidate benchmarks validating a complete report
func BenchmarkValidate(b *testing.B) {
	reportJSON := generateMessagingReportJSON()
	parser := NewParser(false)
	report, err := parser.Parse(reportJSON)
	if err != nil {
		b.Fatalf("Parse failed: %v", err)
	}

	validator := NewValidator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, errs := validator.ValidateReport(report)
		if !valid && len(errs) > 0 {
			// Validation is expected to pass in this case
			b.Logf("Validation error: %v", errs)
		}
	}
}

// BenchmarkValidateMessaging benchmarks validating messaging reports
func BenchmarkValidateMessaging(b *testing.B) {
	reportJSON := generateMessagingReportJSON()
	parser := NewParser(false)
	report, err := parser.Parse(reportJSON)
	if err != nil {
		b.Fatalf("Parse failed: %v", err)
	}

	validator := NewValidator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, _ := validator.ValidateReport(report)
		if !valid {
			b.Logf("Validation failed")
		}
	}
}

// BenchmarkValidateConnection benchmarks validating connection reports
func BenchmarkValidateConnection(b *testing.B) {
	reportJSON := generateConnectionReportJSON()
	parser := NewParser(false)
	report, err := parser.Parse(reportJSON)
	if err != nil {
		b.Fatalf("Parse failed: %v", err)
	}

	validator := NewValidator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, _ := validator.ValidateReport(report)
		if !valid {
			b.Logf("Validation failed")
		}
	}
}

// BenchmarkValidateEmail benchmarks email validation with regex
// This benchmark demonstrates the performance of the pre-compiled email regex
func BenchmarkValidateEmail(b *testing.B) {
	validator := NewValidator()
	// Create a minimal report with emails to validate
	report := &MessagingReport{
		Report: Report{
			XARFVersion: XARFVersion,
			ReportID:    "test-123",
			Timestamp:   time.Now(),
			Reporter: ContactInfo{
				Org:     "Test",
				Contact: "user@example.com",
				Domain:  "example.com",
			},
			Sender: ContactInfo{
				Org:     "Sender",
				Contact: "sender@example.com",
				Domain:  "example.com",
			},
			SourceIdentifier: "192.0.2.1",
			Category:         CategoryMessaging,
			Type:             "spam",
			EvidenceSource:   EvidenceSourceSpamtrap,
		},
		Protocol: "smtp",
		SMTPFrom: "test@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Validate the report multiple times with different email variations
		validator.ValidateReport(report)
	}
}

// BenchmarkValidateDomain benchmarks domain validation with regex
// This benchmark demonstrates the performance of the pre-compiled domain regex
func BenchmarkValidateDomain(b *testing.B) {
	validator := NewValidator()
	// Create reports with different domains to validate
	report := &MessagingReport{
		Report: Report{
			XARFVersion: XARFVersion,
			ReportID:    "test-123",
			Timestamp:   time.Now(),
			Reporter: ContactInfo{
				Org:     "Test",
				Contact: "user@example.com",
				Domain:  "example.com",
			},
			Sender: ContactInfo{
				Org:     "Sender",
				Contact: "sender@example.com",
				Domain:  "example.com",
			},
			SourceIdentifier: "192.0.2.1",
			Category:         CategoryMessaging,
			Type:             "spam",
			EvidenceSource:   EvidenceSourceSpamtrap,
		},
		Protocol: "smtp",
		SMTPFrom: "test@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateReport(report)
	}
}

// BenchmarkGenerateReport benchmarks report generation
func BenchmarkGenerateReport(b *testing.B) {
	gen := NewGenerator()
	confidence := 0.95

	opts := &ReportOptions{
		Category:         CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		Reporter: ContactInfo{
			Org:     "Email Security Provider",
			Contact: "abuse@provider.example.com",
			Domain:  "provider.example.com",
		},
		Sender: ContactInfo{
			Org:     "ISP Customer",
			Contact: "security@customer.example.com",
			Domain:  "customer.example.com",
		},
		EvidenceSource: EvidenceSourceSpamtrap,
		Description:    "Phishing email campaign detected",
		Severity:       SeverityHigh,
		Confidence:     &confidence,
		Tags:           []string{"phishing", "spam"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.GenerateReport(opts)
		if err != nil {
			b.Fatalf("GenerateReport failed: %v", err)
		}
	}
}

// BenchmarkGenerateConnectionReport benchmarks connection report generation
func BenchmarkGenerateConnectionReport(b *testing.B) {
	gen := NewGenerator()
	confidence := 0.99

	opts := &ReportOptions{
		Category:         CategoryConnection,
		Type:             "ddos",
		SourceIdentifier: "192.0.2.200",
		Reporter: ContactInfo{
			Org:     "Network Security",
			Contact: "abuse@security.example.com",
			Domain:  "security.example.com",
		},
		Sender: ContactInfo{
			Org:     "ISP Operations",
			Contact: "noc@isp.example.com",
			Domain:  "isp.example.com",
		},
		EvidenceSource: EvidenceSourceHoneypot,
		Description:    "SYN flood attack detected",
		Severity:       SeverityCritical,
		Confidence:     &confidence,
		Tags:           []string{"ddos", "syn_flood"},
		Occurrence: &Occurrence{
			Start: time.Now().Add(-time.Hour),
			End:   time.Now(),
		},
		Target: &Target{
			IP:   "203.0.113.10",
			Port: 80,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.GenerateReport(opts)
		if err != nil {
			b.Fatalf("GenerateReport failed: %v", err)
		}
	}
}

// BenchmarkGenerateUUID benchmarks UUID generation
func BenchmarkGenerateUUID(b *testing.B) {
	gen := NewGenerator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gen.GenerateUUID()
	}
}

// BenchmarkGenerateHash benchmarks hash generation
func BenchmarkGenerateHash(b *testing.B) {
	gen := NewGenerator()
	data := []byte("Sample payload data for hashing. This is a typical evidence item that needs to be hashed.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.GenerateHash(data, "sha256")
		if err != nil {
			b.Fatalf("GenerateHash failed: %v", err)
		}
	}
}

// BenchmarkGenerateHashSHA512 benchmarks SHA512 hash generation
func BenchmarkGenerateHashSHA512(b *testing.B) {
	gen := NewGenerator()
	data := []byte("Sample payload data for hashing. This is a typical evidence item that needs to be hashed.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.GenerateHash(data, "sha512")
		if err != nil {
			b.Fatalf("GenerateHash failed: %v", err)
		}
	}
}

// BenchmarkGenerateEvidence benchmarks evidence generation with hashing
func BenchmarkGenerateEvidence(b *testing.B) {
	gen := NewGenerator()
	payload := []byte("Email evidence: From: spammer@malicious.com To: user@example.com Subject: Phishing attempt")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.AddEvidence("text/plain", "Email evidence", payload, "sha256")
		if err != nil {
			b.Fatalf("AddEvidence failed: %v", err)
		}
	}
}

// BenchmarkGenerateEvidenceSHA512 benchmarks evidence generation with SHA512 hashing
func BenchmarkGenerateEvidenceSHA512(b *testing.B) {
	gen := NewGenerator()
	payload := []byte("Email evidence: From: spammer@malicious.com To: user@example.com Subject: Phishing attempt")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.AddEvidence("text/plain", "Email evidence", payload, "sha512")
		if err != nil {
			b.Fatalf("AddEvidence failed: %v", err)
		}
	}
}

// BenchmarkParseAndValidate benchmarks the combined operation of parsing and validating
func BenchmarkParseAndValidate(b *testing.B) {
	reportJSON := generateMessagingReportJSON()
	parser := NewParser(false)
	validator := NewValidator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}

		valid, errs := validator.ValidateReport(report)
		if !valid && len(errs) > 0 {
			b.Logf("Validation error: %v", errs)
		}
	}
}

// BenchmarkGenerateAndValidate benchmarks generating and validating reports
func BenchmarkGenerateAndValidate(b *testing.B) {
	gen := NewGenerator()
	validator := NewValidator()
	confidence := 0.95

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
			Org:     "ISP",
			Contact: "noc@isp.example.com",
			Domain:  "isp.example.com",
		},
		EvidenceSource: EvidenceSourceSpamtrap,
		Description:    "Spam report",
		Severity:       SeverityHigh,
		Confidence:     &confidence,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := gen.GenerateReport(opts)
		if err != nil {
			b.Fatalf("GenerateReport failed: %v", err)
		}

		valid, _ := validator.ValidateReport(report)
		if !valid {
			b.Logf("Validation failed")
		}
	}
}

// BenchmarkLargeReportParsing benchmarks parsing a large report with multiple evidence items
func BenchmarkLargeReportParsing(b *testing.B) {
	reportJSON := generateReportWithEvidence()
	parser := NewParser(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
	}
}

// BenchmarkJSONMarshalReport benchmarks JSON marshaling of generated reports
func BenchmarkJSONMarshalReport(b *testing.B) {
	gen := NewGenerator()
	confidence := 0.95

	opts := &ReportOptions{
		Category:         CategoryContent,
		Type:             "phishing_site",
		SourceIdentifier: "192.0.2.300",
		Reporter: ContactInfo{
			Org:     "Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: ContactInfo{
			Org:     "Hosting Provider",
			Contact: "abuse@hosting.example.com",
			Domain:  "hosting.example.com",
		},
		EvidenceSource: EvidenceSourceUserReport,
		Description:    "Phishing content detected",
		Severity:       SeverityHigh,
		Confidence:     &confidence,
		Tags:           []string{"phishing", "web_compromise"},
	}

	report, _ := gen.GenerateReport(opts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(report)
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}

// BenchmarkFullWorkflow benchmarks a complete workflow: generate, marshal, parse, validate
func BenchmarkFullWorkflow(b *testing.B) {
	gen := NewGenerator()
	parser := NewParser(false)
	validator := NewValidator()
	confidence := 0.95

	opts := &ReportOptions{
		Category:         CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		Reporter: ContactInfo{
			Org:     "Email Security",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: ContactInfo{
			Org:     "Customer",
			Contact: "security@customer.example.com",
			Domain:  "customer.example.com",
		},
		EvidenceSource: EvidenceSourceSpamtrap,
		Description:    "Spam detected",
		Severity:       SeverityHigh,
		Confidence:     &confidence,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate report
		report, err := gen.GenerateReport(opts)
		if err != nil {
			b.Fatalf("GenerateReport failed: %v", err)
		}

		// Marshal to JSON
		reportJSON, err := json.Marshal(report)
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}

		// Parse from JSON
		parsedReport, err := parser.Parse(reportJSON)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}

		// Validate
		valid, _ := validator.ValidateReport(parsedReport)
		if !valid {
			b.Logf("Validation failed")
		}
	}
}
