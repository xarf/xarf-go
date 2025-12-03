package xarf

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
)

// Pre-compiled regexes for validation (significant performance improvement)
var (
	emailRegex  = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// Validator provides comprehensive validation for XARF reports
type Validator struct {
	errors []string
}

// NewValidator creates a new Validator instance
func NewValidator() *Validator {
	return &Validator{
		errors: make([]string, 0),
	}
}

// ValidateReport validates a complete XARF report
func (v *Validator) ValidateReport(report interface{}) (
	valid bool, errors []string) {
	v.errors = v.errors[:0]

	switch r := report.(type) {
	case *Report:
		return v.validateBaseReport(r), v.GetErrors()
	case *MessagingReport:
		return v.validateMessagingReport(r), v.GetErrors()
	case *ConnectionReport:
		return v.validateConnectionReport(r), v.GetErrors()
	case *ContentReport:
		return v.validateContentReport(r), v.GetErrors()
	case *VulnerabilityReport:
		return v.validateVulnerabilityReport(r), v.GetErrors()
	case *CopyrightReport:
		return v.validateCopyrightReport(r), v.GetErrors()
	case *InfrastructureReport:
		return v.validateInfrastructureReport(r), v.GetErrors()
	case *ReputationReport:
		return v.validateReputationReport(r), v.GetErrors()
	default:
		v.errors = append(v.errors, "unknown report type")
		return false, v.GetErrors()
	}
}

// validateBaseReport validates the base report fields
func (v *Validator) validateBaseReport(r *Report) (isValid bool) {
	valid := true

	// Validate version
	if r.XARFVersion != XARFVersion {
		v.errors = append(v.errors, fmt.Sprintf("invalid XARF version: %s", r.XARFVersion))
		valid = false
	}

	// Validate report ID (should be UUID format)
	if r.ReportID == "" {
		v.errors = append(v.errors, "report_id is required")
		valid = false
	}

	// Validate category
	if !v.isValidCategory(r.Category) {
		v.errors = append(v.errors, fmt.Sprintf("invalid category: %s", r.Category))
		valid = false
	}

	// Validate reporter
	if !v.validateContactInfo(&r.Reporter, "reporter") {
		valid = false
	}

	// Validate sender
	if !v.validateContactInfo(&r.Sender, "sender") {
		valid = false
	}

	// Validate source identifier (should be IP or domain)
	if r.SourceIdentifier == "" {
		v.errors = append(v.errors, "source_identifier is required")
		valid = false
	}

	// Validate evidence source
	if !v.isValidEvidenceSource(r.EvidenceSource) {
		v.errors = append(v.errors, fmt.Sprintf("invalid evidence_source: %s", r.EvidenceSource))
		valid = false
	}

	// Validate evidence constraints
	if !v.validateEvidenceConstraints(r.Evidence) {
		valid = false
	}

	// Validate optional fields
	if r.Confidence != nil {
		if *r.Confidence < 0.0 || *r.Confidence > 1.0 {
			v.errors = append(v.errors, "confidence must be between 0.0 and 1.0")
			valid = false
		}
	}

	if r.Severity != "" && !v.isValidSeverity(r.Severity) {
		v.errors = append(v.errors, fmt.Sprintf("invalid severity: %s", r.Severity))
		valid = false
	}

	return valid
}

// validateContactInfo validates contact information (reporter or sender)
func (v *Validator) validateContactInfo(c *ContactInfo, fieldName string) (isValid bool) {
	valid := true

	if c.Org == "" {
		v.errors = append(v.errors, fmt.Sprintf("%s.org is required", fieldName))
		valid = false
	}

	if c.Contact == "" {
		v.errors = append(v.errors, fmt.Sprintf("%s.contact is required", fieldName))
		valid = false
	} else if !v.isValidEmail(c.Contact) {
		v.errors = append(v.errors, fmt.Sprintf("invalid %s.contact email: %s", fieldName, c.Contact))
		valid = false
	}

	if c.Domain == "" {
		v.errors = append(v.errors, fmt.Sprintf("%s.domain is required", fieldName))
		valid = false
	} else if !v.isValidDomain(c.Domain) {
		v.errors = append(v.errors, fmt.Sprintf("invalid %s.domain: %s", fieldName, c.Domain))
		valid = false
	}

	return valid
}

// validateMessagingReport validates messaging category reports
func (v *Validator) validateMessagingReport(r *MessagingReport) (isValid bool) {
	valid := v.validateBaseReport(&r.Report)

	// Messaging-specific validation
	validTypes := map[string]bool{
		"spam":           true,
		"bulk_messaging": true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid messaging type: %s", r.Type))
		valid = false
	}

	// Email-specific validation
	if r.Protocol == "smtp" {
		if r.SMTPFrom == "" {
			v.errors = append(v.errors, "smtp_from required for email reports")
			valid = false
		}
		if (r.Type == "spam" || r.Type == "phishing") && r.Subject == "" {
			v.errors = append(v.errors, "subject required for spam/phishing reports")
			valid = false
		}
	}

	return valid
}

// validateConnectionReport validates connection category reports
func (v *Validator) validateConnectionReport(r *ConnectionReport) (isValid bool) {
	valid := v.validateBaseReport(&r.Report)

	// Required fields
	if r.DestinationIP == "" {
		v.errors = append(v.errors, "destination_ip required for connection reports")
		valid = false
	} else if !v.isValidIP(r.DestinationIP) {
		v.errors = append(v.errors, fmt.Sprintf("invalid destination_ip: %s", r.DestinationIP))
		valid = false
	}

	if r.Protocol == "" {
		v.errors = append(v.errors, "protocol required for connection reports")
		valid = false
	}

	// Valid connection types
	validTypes := map[string]bool{
		"ddos":               true,
		"ddos_amplification": true,
		"port_scan":          true,
		"login_attack":       true,
		"auth_failure":       true,
		"sql_injection":      true,
		"reconnaissance":     true,
		"scraping":           true,
		"vulnerability_scan": true,
		"infected_host":      true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid connection type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateContentReport validates content category reports
func (v *Validator) validateContentReport(r *ContentReport) (isValid bool) {
	valid := v.validateBaseReport(&r.Report)

	// URL required
	if r.URL == "" {
		v.errors = append(v.errors, "url required for content reports")
		valid = false
	} else if !v.isValidURL(r.URL) {
		v.errors = append(v.errors, fmt.Sprintf("invalid url: %s", r.URL))
		valid = false
	}

	// Valid content types
	validTypes := map[string]bool{
		"phishing":                true,
		"malware":                 true,
		"fraud":                   true,
		"exposed_data":            true,
		"csam":                    true,
		"csem":                    true,
		"brand_infringement":      true,
		"suspicious_registration": true,
		"remote_compromise":       true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid content type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateVulnerabilityReport validates vulnerability category reports
func (v *Validator) validateVulnerabilityReport(r *VulnerabilityReport) (isValid bool) {
	valid := v.validateBaseReport(&r.Report)

	validTypes := map[string]bool{
		"cve":              true,
		"misconfiguration": true,
		"open_service":     true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid vulnerability type: %s", r.Type))
		valid = false
	}

	// Validate CVSS if present
	if r.CVSS != nil {
		if *r.CVSS < 0.0 || *r.CVSS > 10.0 {
			v.errors = append(v.errors, "CVSS score must be between 0.0 and 10.0")
			valid = false
		}
	}

	return valid
}

// validateCopyrightReport validates copyright category reports
func (v *Validator) validateCopyrightReport(r *CopyrightReport) (isValid bool) {
	valid := v.validateBaseReport(&r.Report)

	validTypes := map[string]bool{
		"copyright":    true,
		"p2p":          true,
		"cyberlocker":  true,
		"ugc_platform": true,
		"link_site":    true,
		"usenet":       true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid copyright type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateInfrastructureReport validates infrastructure category reports
func (v *Validator) validateInfrastructureReport(r *InfrastructureReport) (isValid bool) {
	valid := v.validateBaseReport(&r.Report)

	validTypes := map[string]bool{
		"botnet":             true,
		"compromised_server": true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid infrastructure type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateReputationReport validates reputation category reports
func (v *Validator) validateReputationReport(r *ReputationReport) (isValid bool) {
	valid := v.validateBaseReport(&r.Report)

	validTypes := map[string]bool{
		"blocklist":           true,
		"threat_intelligence": true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid reputation type: %s", r.Type))
		valid = false
	}

	// Validate threat score if present
	if r.ThreatScore != nil {
		if *r.ThreatScore < 0.0 || *r.ThreatScore > 1.0 {
			v.errors = append(v.errors, "threat_score must be between 0.0 and 1.0")
			valid = false
		}
	}

	return valid
}

// validateEvidenceConstraints validates evidence count and size constraints
func (v *Validator) validateEvidenceConstraints(evidence []Evidence) (isValid bool) {
	valid := true

	// Check evidence count limit
	if len(evidence) > MaxEvidenceCount {
		v.errors = append(v.errors, fmt.Sprintf("evidence count exceeds maximum of %d items", MaxEvidenceCount))
		valid = false
	}

	// Check each evidence item size
	for i, ev := range evidence {
		// Check payload size (in bytes)
		payloadSize := len(ev.Payload)
		if payloadSize > MaxEvidenceSize {
			v.errors = append(v.errors, fmt.Sprintf("evidence item %d payload exceeds maximum size of %d bytes (actual: %d)", i, MaxEvidenceSize, payloadSize))
			valid = false
		}

		// Validate content type is not empty
		if ev.ContentType == "" {
			v.errors = append(v.errors, fmt.Sprintf("evidence item %d must have a content_type", i))
			valid = false
		}
	}

	return valid
}

// Helper validation functions

func (v *Validator) isValidCategory(category Category) (valid bool) {
	for _, c := range AllCategories() {
		if c == category {
			return true
		}
	}
	return false
}

func (v *Validator) isValidEvidenceSource(source EvidenceSource) (valid bool) {
	validSources := []EvidenceSource{
		EvidenceSourceSpamtrap,
		EvidenceSourceHoneypot,
		EvidenceSourceUserReport,
		EvidenceSourceAutomatedScan,
		EvidenceSourceManualAnalysis,
		EvidenceSourceVulnerabilityScan,
		EvidenceSourceResearcherAnalysis,
		EvidenceSourceThreatIntelligence,
		EvidenceSourceFlowAnalysis,
		EvidenceSourceIDSIPS,
		EvidenceSourceSIEM,
	}

	for _, s := range validSources {
		if s == source {
			return true
		}
	}
	return false
}

func (v *Validator) isValidSeverity(severity Severity) (valid bool) {
	return severity == SeverityLow ||
		severity == SeverityMedium ||
		severity == SeverityHigh ||
		severity == SeverityCritical
}

func (v *Validator) isValidEmail(email string) (valid bool) {
	// Uses pre-compiled regex at package level for performance
	return emailRegex.MatchString(email)
}

func (v *Validator) isValidIP(ip string) (valid bool) {
	return net.ParseIP(ip) != nil
}

func (v *Validator) isValidURL(urlStr string) (valid bool) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

func (v *Validator) isValidDomain(domain string) (valid bool) {
	// Simple domain validation - check for valid hostname format
	// Must contain at least one dot and valid characters
	if domain == "" {
		return false
	}

	// Uses pre-compiled regex at package level for performance
	return domainRegex.MatchString(domain)
}

// GetErrors returns a copy of validation errors
func (v *Validator) GetErrors() (errors []string) {
	result := make([]string, len(v.errors))
	copy(result, v.errors)
	return result
}
