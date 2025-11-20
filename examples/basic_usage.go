package main

import (
	"encoding/json"
	"fmt"
	"log"

	xarf "github.com/xarf/xarf-go"
)

func main() {
	fmt.Println("XARF Go Library - Basic Usage Examples")
	fmt.Println("========================================\n")

	// Example 1: Generate a Connection Report (DDoS)
	fmt.Println("Example 1: Generating a DDoS Connection Report")
	generateConnectionReport()

	// Example 2: Parse a XARF Report
	fmt.Println("\nExample 2: Parsing a XARF Report")
	parseReport()

	// Example 3: Validate a Report
	fmt.Println("\nExample 3: Validating a Report")
	validateReport()

	// Example 4: On-Behalf-Of Reporting
	fmt.Println("\nExample 4: On-Behalf-Of Reporting")
	onBehalfOfReport()

	// Example 5: Generate with Evidence
	fmt.Println("\nExample 5: Generate Report with Evidence")
	reportWithEvidence()
}

func generateConnectionReport() {
	gen := xarf.NewGenerator()

	opts := xarf.ReportOptions{
		Category:         xarf.CategoryConnection,
		Type:             "ddos",
		SourceIdentifier: "192.0.2.100",
		ReporterContact:  "abuse@example.com",
		ReporterOrg:      "Example Security Team",
		Description:      "Sustained DDoS attack detected targeting our infrastructure",
		Severity:         xarf.SeverityHigh,
	}

	report, err := gen.GenerateReport(opts)
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
			"type": "automated"
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
		fmt.Printf("Parsed DDoS Report:\n")
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
		ReporterContact:  "abuse@example.com",
		ReporterOrg:      "Web Security Team",
		Severity:         xarf.SeverityCritical,
		Confidence:       &conf,
	}

	report, err := gen.GenerateReport(opts)
	if err != nil {
		log.Fatal(err)
	}

	// Validate the report
	validator := xarf.NewValidator()
	valid, errors := validator.ValidateReport(report)

	if valid {
		fmt.Println("Report is valid!")
	} else {
		fmt.Println("Validation errors:")
		for _, err := range errors {
			fmt.Printf("  - %s\n", err)
		}
	}
}

func onBehalfOfReport() {
	gen := xarf.NewGenerator()

	opts := xarf.ReportOptions{
		Category:         xarf.CategoryMessaging,
		Type:             "spam",
		SourceIdentifier: "192.0.2.100",
		ReporterContact:  "abuse@provider.com",
		ReporterOrg:      "Internet Service Provider",
		OnBehalfOf: &xarf.OnBehalfOf{
			Org:     "Customer Organization",
			Contact: "customer@example.com",
		},
		Description: "Spam report submitted on behalf of our customer",
	}

	report, err := gen.GenerateReport(opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Reporter: %s (%s)\n", report.Reporter.Org, report.Reporter.Contact)
	if report.Reporter.OnBehalfOf != nil {
		fmt.Printf("On Behalf Of: %s (%s)\n",
			report.Reporter.OnBehalfOf.Org,
			report.Reporter.OnBehalfOf.Contact)
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
		ReporterContact:  "abuse@example.com",
		ReporterOrg:      "Security Team",
		Evidence:         []xarf.Evidence{*evidence},
		Description:      "Brute force login attack detected",
		Severity:         xarf.SeverityHigh,
	}

	report, err := gen.GenerateReport(opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Report with Evidence:\n")
	fmt.Printf("  Report ID: %s\n", report.ReportID)
	fmt.Printf("  Evidence Items: %d\n", len(report.Evidence))
	if len(report.Evidence) > 0 {
		fmt.Printf("  First Evidence:\n")
		fmt.Printf("    Type: %s\n", report.Evidence[0].ContentType)
		fmt.Printf("    Description: %s\n", report.Evidence[0].Description)
		fmt.Printf("    Hash: %s\n", report.Evidence[0].Hash[:16]+"...")
	}
}
