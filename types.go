package xarf

import (
	"time"
)

// XARFVersion is the current XARF specification version
const XARFVersion = "4.0.0"

// SpecVersion is the XARF specification version this library supports
// This is an alias for XARFVersion for clarity in documentation
const SpecVersion = XARFVersion

// Category represents the XARF report category
type Category string

// All valid XARF categories as per specification
const (
	CategoryMessaging      Category = "messaging"
	CategoryConnection     Category = "connection"
	CategoryContent        Category = "content"
	CategoryCopyright      Category = "copyright"
	CategoryInfrastructure Category = "infrastructure"
	CategoryVulnerability  Category = "vulnerability"
	CategoryReputation     Category = "reputation"
)

// AllCategories returns all valid XARF categories
func AllCategories() []Category {
	return []Category{
		CategoryMessaging,
		CategoryConnection,
		CategoryContent,
		CategoryCopyright,
		CategoryInfrastructure,
		CategoryVulnerability,
		CategoryReputation,
	}
}

// EvidenceSource represents how evidence was collected
type EvidenceSource string

// Evidence sources from core schema examples
const (
	EvidenceSourceSpamtrap            EvidenceSource = "spamtrap"
	EvidenceSourceUserComplaint       EvidenceSource = "user_complaint"
	EvidenceSourceAutomatedFilter     EvidenceSource = "automated_filter"
	EvidenceSourceHoneypot            EvidenceSource = "honeypot"
	EvidenceSourceCrawler             EvidenceSource = "crawler"
	EvidenceSourceUserReport          EvidenceSource = "user_report"
	EvidenceSourceAutomatedScan       EvidenceSource = "automated_scan"
	EvidenceSourceSpamAnalysis        EvidenceSource = "spam_analysis"
	EvidenceSourceFirewallLogs        EvidenceSource = "firewall_logs"
	EvidenceSourceIDSDetection        EvidenceSource = "ids_detection"
	EvidenceSourceFlowAnalysis        EvidenceSource = "flow_analysis"
	EvidenceSourceVulnerabilityScan   EvidenceSource = "vulnerability_scan"
	EvidenceSourceResearcherAnalysis  EvidenceSource = "researcher_analysis"
	EvidenceSourceAutomatedDiscovery  EvidenceSource = "automated_discovery"
	EvidenceSourceTrafficAnalysis     EvidenceSource = "traffic_analysis"
	EvidenceSourceThreatIntelligence  EvidenceSource = "threat_intelligence"
	EvidenceSourceTrafficMonitoring   EvidenceSource = "traffic_monitoring"
	EvidenceSourceManualDiscovery     EvidenceSource = "manual_discovery"
	EvidenceSourceRightsHolder        EvidenceSource = "rights_holder"
	EvidenceSourceSearchEngine        EvidenceSource = "search_engine"
	EvidenceSourceManualMonitoring    EvidenceSource = "manual_monitoring"
	EvidenceSourceSearchMonitoring    EvidenceSource = "search_monitoring"
	EvidenceSourceWatermarkDetection  EvidenceSource = "watermark_detection"
	EvidenceSourceAutomatedDetection  EvidenceSource = "automated_detection"
	EvidenceSourceContentIDMatch      EvidenceSource = "content_id_match"
	EvidenceSourceFingerprintMatch    EvidenceSource = "fingerprint_match"
	EvidenceSourceManualReview        EvidenceSource = "manual_review"
	EvidenceSourceAutomatedMonitoring EvidenceSource = "automated_monitoring"
	EvidenceSourceNewsgroupCrawl      EvidenceSource = "newsgroup_crawl"
	EvidenceSourceNZBIndexMonitoring  EvidenceSource = "nzb_index_monitoring"
	EvidenceSourceVolumeAnalysis      EvidenceSource = "volume_analysis"
	EvidenceSourceContentAnalysis     EvidenceSource = "content_analysis"
	EvidenceSourceReputationFeed      EvidenceSource = "reputation_feed"
	EvidenceSourcePenetrationTesting  EvidenceSource = "penetration_testing"
)

// Severity represents the severity level of the incident
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ContactInfo represents contact information for reporter or sender
type ContactInfo struct {
	Org     string `json:"org"`
	Contact string `json:"contact"`
	Domain  string `json:"domain"`
}

// Evidence represents an evidence item
type Evidence struct {
	ContentType string `json:"content_type"`
	Description string `json:"description"`
	Payload     string `json:"payload"`
	Hash        string `json:"hash,omitempty"`
}

// Occurrence represents the time period of the incident
type Occurrence struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Target represents the target of the abuse
type Target struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Report is the base XARF report structure
type Report struct {
	XARFVersion      string      `json:"xarf_version"`
	ReportID         string      `json:"report_id"`
	Timestamp        time.Time   `json:"timestamp"`
	Reporter         ContactInfo `json:"reporter"`
	Sender           ContactInfo `json:"sender"`
	SourceIdentifier string      `json:"source_identifier"`
	SourcePort       *int        `json:"source_port,omitempty"` // Optional but critical for CGNAT

	// Category field - XARF v4 spec requires "category"
	Category Category `json:"category"`

	Type           string         `json:"type"`
	EvidenceSource EvidenceSource `json:"evidence_source"`

	// Optional fields
	Description string                 `json:"description,omitempty"`
	Evidence    []Evidence             `json:"evidence,omitempty"`
	Severity    Severity               `json:"severity,omitempty"`
	Confidence  *float64               `json:"confidence,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Occurrence  *Occurrence            `json:"occurrence,omitempty"`
	Target      *Target                `json:"target,omitempty"`
	Internal    map[string]interface{} `json:"_internal,omitempty"`

	// Category-specific fields stored as map
	AdditionalFields map[string]interface{} `json:"-"`
}
type MessagingReport struct {
	Report

	// Required for messaging
	Protocol string `json:"protocol,omitempty"`

	// Email-specific fields
	SMTPFrom          string `json:"smtp_from,omitempty"`
	SMTPTo            string `json:"smtp_to,omitempty"`
	Subject           string `json:"subject,omitempty"`
	MessageID         string `json:"message_id,omitempty"`
	SenderDisplayName string `json:"sender_display_name,omitempty"`
	TargetVictim      string `json:"target_victim,omitempty"`
	MessageContent    string `json:"message_content,omitempty"`
}

// ConnectionReport represents a connection category report
type ConnectionReport struct {
	Report

	// Required for connection
	DestinationIP string `json:"destination_ip"`
	Protocol      string `json:"protocol"`

	// Optional connection fields
	DestinationPort *int   `json:"destination_port,omitempty"`
	SourcePort      *int   `json:"source_port,omitempty"`
	AttackType      string `json:"attack_type,omitempty"`
	DurationMinutes *int   `json:"duration_minutes,omitempty"`
	PacketCount     *int64 `json:"packet_count,omitempty"`
	ByteCount       *int64 `json:"byte_count,omitempty"`

	// Login attack specific
	AttemptCount       *int     `json:"attempt_count,omitempty"`
	SuccessfulLogins   *int     `json:"successful_logins,omitempty"`
	UsernamesAttempted []string `json:"usernames_attempted,omitempty"`
	AttackPattern      string   `json:"attack_pattern,omitempty"`
}

// ContentReport represents a content category report
type ContentReport struct {
	Report

	// Required for content
	URL string `json:"url"`

	// Optional content fields
	ContentType            string   `json:"content_type,omitempty"`
	AttackType             string   `json:"attack_type,omitempty"`
	AffectedPages          []string `json:"affected_pages,omitempty"`
	CMSPlatform            string   `json:"cms_platform,omitempty"`
	VulnerabilityExploited string   `json:"vulnerability_exploited,omitempty"`

	// Web hack specific
	AffectedParameters         []string `json:"affected_parameters,omitempty"`
	PayloadDetected            string   `json:"payload_detected,omitempty"`
	DataExposed                []string `json:"data_exposed,omitempty"`
	DatabaseType               string   `json:"database_type,omitempty"`
	RecordsPotentiallyAffected *int     `json:"records_potentially_affected,omitempty"`
}

// VulnerabilityReport represents a vulnerability category report
type VulnerabilityReport struct {
	Report

	// Vulnerability-specific fields
	CVE               string   `json:"cve,omitempty"`
	CVSS              *float64 `json:"cvss,omitempty"`
	AffectedSoftware  string   `json:"affected_software,omitempty"`
	AffectedVersion   string   `json:"affected_version,omitempty"`
	VulnerabilityType string   `json:"vulnerability_type,omitempty"`
	ExploitAvailable  *bool    `json:"exploit_available,omitempty"`
	PatchAvailable    *bool    `json:"patch_available,omitempty"`
	RecommendedAction string   `json:"recommended_action,omitempty"`
	Port              *int     `json:"port,omitempty"`
	Service           string   `json:"service,omitempty"`
}

// CopyrightReport represents a copyright category report
type CopyrightReport struct {
	Report

	// Copyright-specific fields
	WorkTitle        string   `json:"work_title,omitempty"`
	CopyrightHolder  string   `json:"copyright_holder,omitempty"`
	InfringementType string   `json:"infringement_type,omitempty"`
	InfringementURL  string   `json:"infringement_url,omitempty"`
	OriginalWorkURL  string   `json:"original_work_url,omitempty"`
	FileNames        []string `json:"file_names,omitempty"`
	FileHashes       []string `json:"file_hashes,omitempty"`
}

// InfrastructureReport represents an infrastructure category report
type InfrastructureReport struct {
	Report

	// Infrastructure-specific fields
	InfrastructureType string   `json:"infrastructure_type,omitempty"`
	BotnetName         string   `json:"botnet_name,omitempty"`
	C2Servers          []string `json:"c2_servers,omitempty"`
	MalwareFamily      string   `json:"malware_family,omitempty"`
	InfectionVector    string   `json:"infection_vector,omitempty"`
	CompromisedPorts   []int    `json:"compromised_ports,omitempty"`
	Services           []string `json:"services,omitempty"`
}

// ReputationReport represents a reputation category report
type ReputationReport struct {
	Report

	// Reputation-specific fields
	BlocklistName  string    `json:"blocklist_name,omitempty"`
	ListingDate    time.Time `json:"listing_date,omitempty"`
	ListingReason  string    `json:"listing_reason,omitempty"`
	ThreatScore    *float64  `json:"threat_score,omitempty"`
	HistoricalData string    `json:"historical_data,omitempty"`
	RecommendedTTL *int      `json:"recommended_ttl,omitempty"`
}
