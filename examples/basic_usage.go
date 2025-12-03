package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/xarf/xarf-go"
)

func main() {
	fmt.Println("XARF Go Library - Basic Usage Examples")
	fmt.Println("=======================================")

	// Example 1: Generate a simple connection report
	generateConnectionReport()

	// Example 2: Parse a XARF report
	parseReport()

	// Example 3: Validate a report
	validateReport()

	// Example 4: Report with different orgs (on behalf of)
	generateOnBehalfOfReport()

	// Example 5: Report with evidence
	reportWithEvidence()
}

func generateConnectionReport() {
	gen := xarf.NewGenerator()

	opts := xarf.ReportOptions{
		Category:         xarf.CategoryConnection,
		Type:             "ddos",
		SourceIdentifier: "192.0.2.100",
		Reporter: xarf.ContactInfo{
			Org:     "Example Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: xarf.ContactInfo{
			Org:     "Example Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Description: "Sustained DDoS attack detected targeting our infrastructure",
		Severity:    xarf.SeverityHigh,
	}

	report, err := gen.GenerateReport(&opts)
	if err != nil {
		log.Fatal(err)
	}

	jsonData, _ := json.MarshalIndent(report, "", "  ")
	fmt.Printf("Generated Report:\n%s\n", jsonData)
}

func parseReport() {
	jsonData := []byte(`{
		"xarf_version": "4.0.0",
		"report_id": "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": "2024-01-15T10:30:00Z",
		"reporter": {
			"org": "Security Operations Center",
			"contact": "abuse@example.com",
			"domain": "example.com"
		},
		"sender": {
			"org": "Security Operations Center",
			"contact": "abuse@example.com",
			"domain": "example.com"
		},
		"source_identifier": "192.0.2.100",
		"category": "connection",
		"type": "ddos",
		"evidence_source": "honeypot",
		"destination_ip": "203.0.113.10",
		"protocol": "tcp",
		"destination_port": 80
	}`)

	parser := xarf.NewParser(false)
	result, err := parser.Parse(jsonData)
	if err != nil {
		log.Fatal(err)
	}

	// Type assertion to access category-specific fields
	if connReport, ok := result.(*xarf.ConnectionReport); ok {
		fmt.Printf("\nParsed DDoS Report:\n")
		fmt.Printf("  Source: %s\n", connReport.SourceIdentifier)
		fmt.Printf("  Target: %s:%v\n", connReport.DestinationIP, *connReport.DestinationPort)
		fmt.Printf("  Protocol: %s\n", connReport.Protocol)
		fmt.Printf("  Type: %s\n", connReport.Type)
	}
}

func validateReport() {
	gen := xarf.NewGenerator()

	// Create a report
	conf := 0.95
	opts := xarf.ReportOptions{
		Category:         xarf.CategoryContent,
		Type:             "phishing_site",
		SourceIdentifier: "192.0.2.100",
		Reporter: xarf.ContactInfo{
			Org:     "Web Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: xarf.ContactInfo{
			Org:     "Web Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Severity:   xarf.SeverityCritical,
		Confidence: &conf,
	}

	report, err := gen.GenerateReport(&opts)
	if err != nil {
		log.Fatal(err)
	}

	// Validate the report
	validator := xarf.NewValidator()
	valid, errors := validator.ValidateReport(report)

	fmt.Println("\nValidation Result:")
	if valid {
		fmt.Println("  Report is valid!")
	} else {
		fmt.Println("  Validation errors:")
		for _, err := range errors {
			fmt.Printf("    - %s\n", err)
		}
	}
}

func generateOnBehalfOfReport() {
	gen := xarf.NewGenerator()

	opts := xarf.ReportOptions{
		Category:         xarf.CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.250",
		Reporter: xarf.ContactInfo{
			Org:     "Service Provider",
			Contact: "abuse@provider.com",
			Domain:  "provider.com",
		},
		Sender: xarf.ContactInfo{
			Org:     "Customer Organization",
			Contact: "abuse@customer.com",
			Domain:  "customer.com",
		},
		Description: "Spam report submitted on behalf of client",
		Severity:    xarf.SeverityMedium,
	}

	report, err := gen.GenerateReport(&opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n--- On Behalf Of Report ---")
	fmt.Printf("Report ID: %s\n", report.ReportID)
	fmt.Printf("Reporter Org: %s\n", report.Reporter.Org)
	fmt.Printf("Sender Org: %s\n", report.Sender.Org)
	if report.Reporter.Org != report.Sender.Org {
		fmt.Printf("Report is on behalf of: %s\n", report.Sender.Org)
	}
}

func reportWithEvidence() {
	gen := xarf.NewGenerator()

	// Generate evidence
	payload := []byte("Sample log data showing malicious activity")
	evidence, err := gen.AddEvidence(
		"text/plain",
		"Server log excerpt showing attack pattern",
		payload,
		"sha256",
	)
	if err != nil {
		log.Fatal(err)
	}

	opts := xarf.ReportOptions{
		Category:         xarf.CategoryConnection,
		Type:             "login_attack",
		SourceIdentifier: "192.0.2.100",
		Reporter: xarf.ContactInfo{
			Org:     "Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Sender: xarf.ContactInfo{
			Org:     "Security Team",
			Contact: "abuse@example.com",
			Domain:  "example.com",
		},
		Evidence:    []xarf.Evidence{*evidence},
		Description: "Brute force login attack detected",
		Severity:    xarf.SeverityHigh,
	}

	report, err := gen.GenerateReport(&opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n--- Report with Evidence ---")
	fmt.Printf("Report ID: %s\n", report.ReportID)
	fmt.Printf("Evidence Items: %d\n", len(report.Evidence))
	if len(report.Evidence) > 0 {
		fmt.Printf("  Content Type: %s\n", report.Evidence[0].ContentType)
		fmt.Printf("  Hash: %s\n", report.Evidence[0].Hash)
	}
}
