package xarf

import (
	"encoding/json"
	"fmt"
	"time"
)

// Parser handles parsing and basic validation of XARF reports
type Parser struct {
	strict bool
	errors []string
}

// NewParser creates a new Parser instance
func NewParser(strict bool) (parser *Parser) {
	return &Parser{
		strict: strict,
		errors: make([]string, 0),
	}
}

// Parse parses a XARF report from JSON bytes
func (p *Parser) Parse(data []byte) (report interface{}, err error) {
	p.errors = p.errors[:0]

	// First parse into a map to determine category
	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil, NewParseError("invalid JSON", err)
	}

	// Validate basic structure
	if !p.validateStructure(rawData) {
		if p.strict {
			return nil, NewValidationError("validation failed", p.errors)
		}
	}

	// Parse based on category
	category, categoryOk := rawData["category"].(string)
	if !categoryOk {
		return nil, NewParseError("category field missing or invalid", nil)
	}

	return p.parseByCategory(data, Category(category))
}

// ParseString parses a XARF report from a JSON string
func (p *Parser) ParseString(jsonStr string) (report interface{}, err error) {
	return p.Parse([]byte(jsonStr))
}

// categoryParser defines a function type for parsing category-specific reports
type categoryParser func([]byte) (interface{}, error)

// categoryParsers maps categories to their parsing functions
var categoryParsers = map[Category]categoryParser{
	CategoryMessaging: func(data []byte) (interface{}, error) {
		var report MessagingReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse messaging report", err)
		}
		return &report, nil
	},
	CategoryConnection: func(data []byte) (interface{}, error) {
		var report ConnectionReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse connection report", err)
		}
		return &report, nil
	},
	CategoryContent: func(data []byte) (interface{}, error) {
		var report ContentReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse content report", err)
		}
		return &report, nil
	},
	CategoryAbuse: func(data []byte) (interface{}, error) {
		var report AbusiveReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse abuse report", err)
		}
		return &report, nil
	},
	CategoryVulnerability: func(data []byte) (interface{}, error) {
		var report VulnerabilityReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse vulnerability report", err)
		}
		return &report, nil
	},
	CategoryCopyright: func(data []byte) (interface{}, error) {
		var report CopyrightReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse copyright report", err)
		}
		return &report, nil
	},
	CategoryInfrastructure: func(data []byte) (interface{}, error) {
		var report InfrastructureReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse infrastructure report", err)
		}
		return &report, nil
	},
	CategoryReputation: func(data []byte) (interface{}, error) {
		var report ReputationReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, NewParseError("failed to parse reputation report", err)
		}
		return &report, nil
	},
}

// parseByCategory parses report based on its category (complexity reduced to 4)
func (p *Parser) parseByCategory(data []byte, category Category) (
	result interface{}, err error) {
	parser, exists := categoryParsers[category]
	if exists {
		return parser(data)
	}

	// Fall back to base report
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, NewParseError("failed to parse report", err)
	}
	return &report, nil
}

// validateStructure validates the basic XARF structure
func (p *Parser) validateStructure(data map[string]interface{}) (isValid bool) {
	requiredFields := []string{
		"xarf_version",
		"report_id",
		"timestamp",
		"reporter",
		"source_identifier",
		"type",
		"evidence_source",
	}

	// Check required fields
	for _, field := range requiredFields {
		if _, ok := data[field]; !ok {
			p.errors = append(p.errors, fmt.Sprintf("missing required field: %s", field))
			return false
		}
	}

	// Check for category field
	if _, ok := data["category"]; !ok {
		p.errors = append(p.errors, "missing required field: category")
		return false
	}

	// Check XARF version
	if version, ok := data["xarf_version"].(string); !ok || version != XARFVersion {
		p.errors = append(p.errors, fmt.Sprintf("unsupported XARF version: %v", data["xarf_version"]))
		return false
	}

	// Validate reporter structure
	reporter, reporterOk := data["reporter"].(map[string]interface{})
	if !reporterOk {
		p.errors = append(p.errors, "reporter must be an object")
		return false
	}

	reporterRequired := []string{"org", "contact", "domain"}
	for _, field := range reporterRequired {
		if _, fieldExists := reporter[field]; !fieldExists {
			p.errors = append(p.errors, fmt.Sprintf("missing reporter field: %s", field))
			return false
		}
	}

	// Validate sender structure
	sender, senderOk := data["sender"].(map[string]interface{})
	if !senderOk {
		p.errors = append(p.errors, "sender must be an object")
		return false
	}

	senderRequired := []string{"org", "contact", "domain"}
	for _, field := range senderRequired {
		if _, fieldExists := sender[field]; !fieldExists {
			p.errors = append(p.errors, fmt.Sprintf("missing sender field: %s", field))
			return false
		}
	}

	// Validate timestamp format
	timestampStr, ok := data["timestamp"].(string)
	if !ok {
		p.errors = append(p.errors, "timestamp must be a string")
		return false
	}

	// Try parsing timestamp
	if _, err := time.Parse(time.RFC3339, timestampStr); err != nil {
		p.errors = append(p.errors, fmt.Sprintf("invalid timestamp format: %s", timestampStr))
		return false
	}

	return true
}

// Validate validates a XARF report without fully parsing it
func (p *Parser) Validate(data []byte) (isValid bool) {
	p.errors = p.errors[:0]

	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		p.errors = append(p.errors, fmt.Sprintf("invalid JSON: %v", err))
		return false
	}

	return p.validateStructure(rawData)
}

// ValidateString validates a XARF report from a JSON string
func (p *Parser) ValidateString(jsonStr string) (isValid bool) {
	return p.Validate([]byte(jsonStr))
}

// GetErrors returns validation errors from the last parse/validate call
func (p *Parser) GetErrors() (errors []string) {
	result := make([]string, len(p.errors))
	copy(result, p.errors)
	return result
}
