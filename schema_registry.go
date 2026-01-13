package xarf

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xarf/xarf-go/schemas"
)

// Note: The schemas package is a subpackage containing embedded JSON schemas

// SchemaRegistry provides centralized access to schema-derived validation rules.
// It extracts validation rules dynamically from XARF JSON schemas,
// eliminating hardcoded validation lists throughout the codebase.
type SchemaRegistry struct {
	coreSchema      map[string]interface{}
	typeSchemas     map[string]map[string]interface{} // key: "category/type"
	categories      []Category
	typesPerCat     map[Category][]string
	evidenceSources []EvidenceSource
	severities      []Severity
	requiredFields  []string
	loaded          bool
	mu              sync.RWMutex
}

var (
	registryInstance *SchemaRegistry
	registryOnce     sync.Once
)

// GetSchemaRegistry returns the singleton SchemaRegistry instance.
func GetSchemaRegistry() *SchemaRegistry {
	registryOnce.Do(func() {
		registryInstance = &SchemaRegistry{
			typeSchemas: make(map[string]map[string]interface{}),
			typesPerCat: make(map[Category][]string),
		}
		if err := registryInstance.load(); err != nil {
			// Log error but don't panic - validation will fall back to hardcoded rules
			fmt.Printf("Warning: failed to load schemas: %v\n", err)
		}
	})
	return registryInstance
}

// ResetRegistry resets the singleton instance (useful for testing).
func ResetRegistry() {
	registryOnce = sync.Once{}
	registryInstance = nil
}

// load loads all schemas from the embedded filesystem.
func (r *SchemaRegistry) load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Load core schema
	coreData, err := schemas.FS.ReadFile("xarf-core.json")
	if err != nil {
		return fmt.Errorf("failed to read xarf-core.json: %w", err)
	}

	if err := json.Unmarshal(coreData, &r.coreSchema); err != nil {
		return fmt.Errorf("failed to parse xarf-core.json: %w", err)
	}

	// Extract categories from core schema
	r.extractCategories()

	// Extract evidence sources from core schema
	r.extractEvidenceSources()

	// Extract severities
	r.extractSeverities()

	// Extract required fields
	r.extractRequiredFields()

	// Load type schemas
	if err := r.loadTypeSchemas(); err != nil {
		return fmt.Errorf("failed to load type schemas: %w", err)
	}

	r.loaded = true
	return nil
}

// extractCategories extracts valid categories from the core schema.
func (r *SchemaRegistry) extractCategories() {
	props, ok := r.coreSchema["properties"].(map[string]interface{})
	if !ok {
		return
	}

	catProp, ok := props["category"].(map[string]interface{})
	if !ok {
		return
	}

	enumVals, ok := catProp["enum"].([]interface{})
	if !ok {
		return
	}

	r.categories = make([]Category, 0, len(enumVals))
	for _, v := range enumVals {
		if s, ok := v.(string); ok {
			r.categories = append(r.categories, Category(s))
		}
	}
}

// extractEvidenceSources extracts valid evidence sources from the core schema and type schemas.
func (r *SchemaRegistry) extractEvidenceSources() {
	// Use a set to avoid duplicates
	sourceSet := make(map[string]bool)

	// Extract from core schema
	r.extractCoreEvidenceSources(sourceSet)

	// Extract from type schemas (they have enum values)
	r.extractTypeEvidenceSources(sourceSet)

	// Convert set to slice
	r.evidenceSources = make([]EvidenceSource, 0, len(sourceSet))
	for source := range sourceSet {
		r.evidenceSources = append(r.evidenceSources, EvidenceSource(source))
	}
}

// extractCoreEvidenceSources extracts evidence sources from the core schema.
func (r *SchemaRegistry) extractCoreEvidenceSources(sourceSet map[string]bool) {
	props, ok := r.coreSchema["properties"].(map[string]interface{})
	if !ok {
		return
	}

	esProp, ok := props["evidence_source"].(map[string]interface{})
	if !ok {
		return
	}

	// Try enum first
	if enumVals, ok := esProp["enum"].([]interface{}); ok {
		for _, v := range enumVals {
			if s, ok := v.(string); ok {
				sourceSet[s] = true
			}
		}
		return
	}

	// Fall back to examples
	if examples, ok := esProp["examples"].([]interface{}); ok {
		for _, v := range examples {
			if s, ok := v.(string); ok {
				sourceSet[s] = true
			}
		}
	}
}

// extractTypeEvidenceSources extracts evidence sources from type schemas.
func (r *SchemaRegistry) extractTypeEvidenceSources(sourceSet map[string]bool) {
	for _, schema := range r.typeSchemas {
		r.extractEvidenceSourcesFromSchema(schema, sourceSet)
	}
}

// extractEvidenceSourcesFromSchema extracts evidence sources from a single schema.
func (r *SchemaRegistry) extractEvidenceSourcesFromSchema(schema map[string]interface{}, sourceSet map[string]bool) {
	allOf, ok := schema["allOf"].([]interface{})
	if !ok {
		return
	}

	for _, item := range allOf {
		subSchema, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		props, ok := subSchema["properties"].(map[string]interface{})
		if !ok {
			continue
		}

		esProp, ok := props["evidence_source"].(map[string]interface{})
		if !ok {
			continue
		}

		enumVals, ok := esProp["enum"].([]interface{})
		if !ok {
			continue
		}

		for _, v := range enumVals {
			if s, ok := v.(string); ok {
				sourceSet[s] = true
			}
		}
	}
}

// extractSeverities extracts valid severity levels.
func (r *SchemaRegistry) extractSeverities() {
	// Severities are standard across XARF
	r.severities = []Severity{
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}
}

// extractRequiredFields extracts required fields from the core schema.
func (r *SchemaRegistry) extractRequiredFields() {
	required, ok := r.coreSchema["required"].([]interface{})
	if !ok {
		return
	}

	r.requiredFields = make([]string, 0, len(required))
	for _, v := range required {
		if s, ok := v.(string); ok {
			r.requiredFields = append(r.requiredFields, s)
		}
	}
}

// loadTypeSchemas loads all type-specific schemas from the types directory.
func (r *SchemaRegistry) loadTypeSchemas() error {
	entries, err := schemas.FS.ReadDir("types")
	if err != nil {
		return fmt.Errorf("failed to read types directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// Skip base schemas
		if strings.Contains(entry.Name(), "-base.json") {
			continue
		}

		// Parse filename: {category}-{type}.json
		name := strings.TrimSuffix(entry.Name(), ".json")
		parts := strings.SplitN(name, "-", 2)
		if len(parts) != 2 {
			continue
		}

		category := Category(parts[0])
		typeName := strings.ReplaceAll(parts[1], "-", "_")

		// Load schema
		data, err := schemas.FS.ReadFile(filepath.Join("types", entry.Name()))
		if err != nil {
			continue
		}

		var schema map[string]interface{}
		if err := json.Unmarshal(data, &schema); err != nil {
			continue
		}

		// Store schema
		key := fmt.Sprintf("%s/%s", category, typeName)
		r.typeSchemas[key] = schema

		// Add to types per category
		r.typesPerCat[category] = append(r.typesPerCat[category], typeName)
	}

	return nil
}

// IsLoaded returns true if schemas were successfully loaded.
func (r *SchemaRegistry) IsLoaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loaded
}

// GetCategories returns all valid XARF categories.
func (r *SchemaRegistry) GetCategories() []Category {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.categories) == 0 {
		// Fall back to hardcoded categories
		return AllCategories()
	}
	return r.categories
}

// GetTypesForCategory returns valid types for a specific category.
func (r *SchemaRegistry) GetTypesForCategory(category Category) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if types, ok := r.typesPerCat[category]; ok {
		return types
	}
	return nil
}

// GetEvidenceSources returns all valid evidence sources.
func (r *SchemaRegistry) GetEvidenceSources() []EvidenceSource {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.evidenceSources) == 0 {
		// Fall back to common evidence sources from schema
		return []EvidenceSource{
			EvidenceSourceSpamtrap,
			EvidenceSourceUserComplaint,
			EvidenceSourceAutomatedFilter,
			EvidenceSourceHoneypot,
			EvidenceSourceCrawler,
			EvidenceSourceUserReport,
			EvidenceSourceAutomatedScan,
			EvidenceSourceFirewallLogs,
			EvidenceSourceIDSDetection,
			EvidenceSourceFlowAnalysis,
			EvidenceSourceVulnerabilityScan,
			EvidenceSourceResearcherAnalysis,
			EvidenceSourceAutomatedDiscovery,
			EvidenceSourceTrafficAnalysis,
			EvidenceSourceThreatIntelligence,
		}
	}
	return r.evidenceSources
}

// GetSeverities returns all valid severity levels.
func (r *SchemaRegistry) GetSeverities() []Severity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.severities
}

// GetRequiredFields returns the list of required fields from the core schema.
func (r *SchemaRegistry) GetRequiredFields() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.requiredFields
}

// IsValidCategory checks if a category is valid.
func (r *SchemaRegistry) IsValidCategory(category Category) bool {
	for _, c := range r.GetCategories() {
		if c == category {
			return true
		}
	}
	return false
}

// IsValidType checks if a type is valid for a category.
func (r *SchemaRegistry) IsValidType(category Category, typeName string) bool {
	types := r.GetTypesForCategory(category)
	for _, t := range types {
		if t == typeName {
			return true
		}
	}
	return false
}

// IsValidEvidenceSource checks if an evidence source is valid.
func (r *SchemaRegistry) IsValidEvidenceSource(source EvidenceSource) bool {
	for _, s := range r.GetEvidenceSources() {
		if s == source {
			return true
		}
	}
	return false
}

// IsValidSeverity checks if a severity is valid.
func (r *SchemaRegistry) IsValidSeverity(severity Severity) bool {
	for _, s := range r.GetSeverities() {
		if s == severity {
			return true
		}
	}
	return false
}

// GetTypeSchema returns the schema for a specific category/type combination.
func (r *SchemaRegistry) GetTypeSchema(category Category, typeName string) map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s/%s", category, typeName)
	return r.typeSchemas[key]
}

// GetCoreSchema returns the core schema.
func (r *SchemaRegistry) GetCoreSchema() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.coreSchema
}

// IsFieldRequired checks if a field is required according to the core schema.
func (r *SchemaRegistry) IsFieldRequired(fieldName string) bool {
	for _, f := range r.GetRequiredFields() {
		if f == fieldName {
			return true
		}
	}
	return false
}
