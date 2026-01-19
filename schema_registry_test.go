package xarf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSchemaRegistry(t *testing.T) {
	// Reset to ensure clean state
	ResetRegistry()

	registry := GetSchemaRegistry()
	require.NotNil(t, registry)

	// Should return same instance (singleton)
	registry2 := GetSchemaRegistry()
	assert.Same(t, registry, registry2)
}

func TestSchemaRegistryIsLoaded(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	assert.True(t, registry.IsLoaded())
}

func TestSchemaRegistryGetCategories(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	categories := registry.GetCategories()
	assert.NotEmpty(t, categories)

	// Should contain standard categories
	categoryStrings := make([]string, len(categories))
	for i, c := range categories {
		categoryStrings[i] = string(c)
	}

	assert.Contains(t, categoryStrings, "messaging")
	assert.Contains(t, categoryStrings, "connection")
	assert.Contains(t, categoryStrings, "content")
}

func TestSchemaRegistryGetTypesForCategory(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	t.Run("messaging category", func(t *testing.T) {
		types := registry.GetTypesForCategory(CategoryMessaging)
		assert.NotEmpty(t, types)
		assert.Contains(t, types, "spam")
	})

	t.Run("connection category", func(t *testing.T) {
		types := registry.GetTypesForCategory(CategoryConnection)
		assert.NotEmpty(t, types)
	})

	t.Run("unknown category", func(t *testing.T) {
		types := registry.GetTypesForCategory(Category("unknown"))
		assert.Empty(t, types)
	})
}

func TestSchemaRegistryGetEvidenceSources(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	sources := registry.GetEvidenceSources()
	assert.NotEmpty(t, sources)

	// Should contain common evidence sources
	sourceStrings := make([]string, len(sources))
	for i, s := range sources {
		sourceStrings[i] = string(s)
	}

	// Check for at least some common sources
	hasSpamtrap := false
	hasHoneypot := false
	for _, s := range sourceStrings {
		if s == "spamtrap" {
			hasSpamtrap = true
		}
		if s == "honeypot" {
			hasHoneypot = true
		}
	}
	assert.True(t, hasSpamtrap || hasHoneypot, "Should have at least one common evidence source")
}

func TestSchemaRegistryGetSeverities(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	severities := registry.GetSeverities()
	assert.NotEmpty(t, severities)
	assert.Len(t, severities, 4) // low, medium, high, critical
}

func TestSchemaRegistryGetRequiredFields(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	fields := registry.GetRequiredFields()
	assert.NotEmpty(t, fields)

	// Should contain standard required fields
	assert.Contains(t, fields, "xarf_version")
	assert.Contains(t, fields, "report_id")
	assert.Contains(t, fields, "category")
}

func TestSchemaRegistryIsValidCategory(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	tests := []struct {
		category Category
		valid    bool
	}{
		{CategoryMessaging, true},
		{CategoryConnection, true},
		{CategoryContent, true},
		{CategoryVulnerability, true},
		{CategoryCopyright, true},
		{CategoryInfrastructure, true},
		{CategoryReputation, true},
		{Category("invalid"), false},
		{Category(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			result := registry.IsValidCategory(tt.category)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestSchemaRegistryIsValidType(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	tests := []struct {
		category Category
		typeName string
		valid    bool
	}{
		{CategoryMessaging, "spam", true},
		{CategoryConnection, "ddos", true},
		{CategoryContent, "phishing", true},
		{CategoryMessaging, "invalid_type", false},
		{Category("invalid"), "spam", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.category)+"/"+tt.typeName, func(t *testing.T) {
			result := registry.IsValidType(tt.category, tt.typeName)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestSchemaRegistryIsValidEvidenceSource(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	tests := []struct {
		source EvidenceSource
		valid  bool
	}{
		{EvidenceSourceSpamtrap, true},
		{EvidenceSourceHoneypot, true},
		{EvidenceSourceUserReport, true},
		{EvidenceSource("invalid_source"), false},
		{EvidenceSource(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.source), func(t *testing.T) {
			result := registry.IsValidEvidenceSource(tt.source)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestSchemaRegistryIsValidSeverity(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	tests := []struct {
		severity Severity
		valid    bool
	}{
		{SeverityLow, true},
		{SeverityMedium, true},
		{SeverityHigh, true},
		{SeverityCritical, true},
		{Severity("invalid"), false},
		{Severity(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := registry.IsValidSeverity(tt.severity)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestSchemaRegistryGetTypeSchema(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	t.Run("existing type schema", func(t *testing.T) {
		schema := registry.GetTypeSchema(CategoryMessaging, "spam")
		assert.NotNil(t, schema)
	})

	t.Run("non-existing type schema", func(t *testing.T) {
		schema := registry.GetTypeSchema(Category("invalid"), "invalid")
		assert.Nil(t, schema)
	})
}

func TestSchemaRegistryGetCoreSchema(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	schema := registry.GetCoreSchema()
	assert.NotNil(t, schema)

	// Should have properties
	_, hasProperties := schema["properties"]
	assert.True(t, hasProperties)
}

func TestSchemaRegistryIsFieldRequired(t *testing.T) {
	ResetRegistry()
	registry := GetSchemaRegistry()

	tests := []struct {
		field    string
		required bool
	}{
		{"xarf_version", true},
		{"report_id", true},
		{"category", true},
		{"optional_field", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := registry.IsFieldRequired(tt.field)
			assert.Equal(t, tt.required, result)
		})
	}
}

func TestResetRegistry(t *testing.T) {
	// Get initial instance
	registry1 := GetSchemaRegistry()
	require.NotNil(t, registry1)

	// Reset
	ResetRegistry()

	// Get new instance - should be different
	registry2 := GetSchemaRegistry()
	require.NotNil(t, registry2)

	// Both should be loaded
	assert.True(t, registry1.IsLoaded())
	assert.True(t, registry2.IsLoaded())
}
