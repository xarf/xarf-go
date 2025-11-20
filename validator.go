package xarf

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
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
func (v *Validator) ValidateReport(report interface{}) (bool, []string) {
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
	case *AbusiveReport:
		return v.validateAbusiveReport(r), v.GetErrors()
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
func (v *Validator) validateBaseReport(r *Report) bool {
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
	if !v.validateReporter(&r.Reporter) {
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

// validateReporter validates reporter information
func (v *Validator) validateReporter(r *Reporter) bool {
	valid := true

	if r.Contact == "" {
		v.errors = append(v.errors, "reporter.contact is required")
		valid = false
	} else if !v.isValidEmail(r.Contact) {
		v.errors = append(v.errors, fmt.Sprintf("invalid reporter.contact email: %s", r.Contact))
		valid = false
	}

	if !v.isValidReporterType(r.Type) {
		v.errors = append(v.errors, fmt.Sprintf("invalid reporter.type: %s", r.Type))
		valid = false
	}

	// Validate on_behalf_of if present
	if r.OnBehalfOf != nil {
		if r.OnBehalfOf.Org == "" {
			v.errors = append(v.errors, "on_behalf_of.org is required when on_behalf_of is present")
			valid = false
		}
		if r.OnBehalfOf.Contact != "" && !v.isValidEmail(r.OnBehalfOf.Contact) {
			v.errors = append(v.errors, fmt.Sprintf("invalid on_behalf_of.contact email: %s", r.OnBehalfOf.Contact))
			valid = false
		}
	}

	return valid
}

// validateMessagingReport validates messaging category reports
func (v *Validator) validateMessagingReport(r *MessagingReport) bool {
	valid := v.validateBaseReport(&r.Report)

	// Messaging-specific validation
	validTypes := map[string]bool{
		"spam":                true,
		"phishing":            true,
		"social_engineering":  true,
		"bulk_messaging":      true,
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
func (v *Validator) validateConnectionReport(r *ConnectionReport) bool {
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
		"ddos":           true,
		"port_scan":      true,
		"login_attack":   true,
		"ip_spoofing":    true,
		"compromised":    true,
		"botnet":         true,
		"malicious_traffic": true,
		"sql_injection":  true,
		"reconnaissance": true,
		"scraping":       true,
		"vuln_scanning":  true,
		"bot":            true,
		"infected_host":  true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid connection type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateContentReport validates content category reports
func (v *Validator) validateContentReport(r *ContentReport) bool {
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
		"phishing_site":        true,
		"malware_distribution": true,
		"defacement":           true,
		"spamvertised":         true,
		"web_hack":             true,
		"illegal":              true,
		"malicious":            true,
		"policy_violation":     true,
		"phishing":             true,
		"malware":              true,
		"fraud":                true,
		"exposed_data":         true,
		"csam":                 true,
		"csem":                 true,
		"brand_infringement":   true,
		"suspicious_registration": true,
		"remote_compromise":    true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid content type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateAbusiveReport validates abuse category reports
func (v *Validator) validateAbusiveReport(r *AbusiveReport) bool {
	valid := v.validateBaseReport(&r.Report)

	validTypes := map[string]bool{
		"ddos":     true,
		"malware":  true,
		"phishing": true,
		"spam":     true,
		"scanner":  true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid abuse type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateVulnerabilityReport validates vulnerability category reports
func (v *Validator) validateVulnerabilityReport(r *VulnerabilityReport) bool {
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
func (v *Validator) validateCopyrightReport(r *CopyrightReport) bool {
	valid := v.validateBaseReport(&r.Report)

	validTypes := map[string]bool{
		"infringement": true,
		"dmca":         true,
		"trademark":    true,
		"p2p":          true,
		"cyberlocker":  true,
		"link_site":    true,
		"ugc_platform": true,
		"usenet":       true,
		"copyright":    true,
	}

	if !validTypes[r.Type] {
		v.errors = append(v.errors, fmt.Sprintf("invalid copyright type: %s", r.Type))
		valid = false
	}

	return valid
}

// validateInfrastructureReport validates infrastructure category reports
func (v *Validator) validateInfrastructureReport(r *InfrastructureReport) bool {
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
func (v *Validator) validateReputationReport(r *ReputationReport) bool {
	valid := v.validateBaseReport(&r.Report)

	validTypes := map[string]bool{
		"blocklist":            true,
		"threat_intelligence":  true,
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

// Helper validation functions

func (v *Validator) isValidCategory(category Category) bool {
	for _, c := range AllCategories() {
		if c == category {
			return true
		}
	}
	return false
}

func (v *Validator) isValidEvidenceSource(source EvidenceSource) bool {
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

func (v *Validator) isValidSeverity(severity Severity) bool {
	return severity == SeverityLow ||
		severity == SeverityMedium ||
		severity == SeverityHigh ||
		severity == SeverityCritical
}

func (v *Validator) isValidReporterType(t ReporterType) bool {
	return t == ReporterTypeAutomated ||
		t == ReporterTypeManual ||
		t == ReporterTypeHybrid
}

func (v *Validator) isValidEmail(email string) bool {
	// Simple email validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (v *Validator) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (v *Validator) isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

// GetErrors returns a copy of validation errors
func (v *Validator) GetErrors() []string {
	result := make([]string, len(v.errors))
	copy(result, v.errors)
	return result
}
