package xarf

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/xarf/xarf-go/schemas"
)

// SchemaValidator validates XARF reports against the embedded JSON schemas.
//
// Validation is performed against the self-contained master schema
// (xarf-v4-master.json), which composes the core schema and every
// category/type schema via allOf + if/then — mirroring the JavaScript library.
// A second, strict variant promotes every `x-recommended` property to required.
type SchemaValidator struct {
	masterSchema *jsonschema.Schema
	strictMaster *jsonschema.Schema
	coreSchema   *jsonschema.Schema
	typeSchemas  map[string]*jsonschema.Schema // key: "category/type"
	loaded       bool
	mu           sync.RWMutex
}

// Schemas declare full-URL $ids, and $refs resolve against them, so resources
// must be registered under those canonical URLs.
const (
	schemaBaseURL  = "https://xarf.org/schemas/v4"
	masterSchemaID = schemaBaseURL + "/xarf-v4-master.json"
	coreSchemaID   = schemaBaseURL + "/xarf-core.json"
)

var (
	schemaValidatorInstance *SchemaValidator
	schemaValidatorOnce     sync.Once
)

// GetSchemaValidator returns the singleton SchemaValidator instance.
func GetSchemaValidator() *SchemaValidator {
	schemaValidatorOnce.Do(func() {
		schemaValidatorInstance = &SchemaValidator{
			typeSchemas: make(map[string]*jsonschema.Schema),
		}
		if err := schemaValidatorInstance.load(); err != nil {
			fmt.Printf("Warning: failed to load schema validator: %v\n", err)
		}
	})
	return schemaValidatorInstance
}

// ResetSchemaValidator resets the singleton instance (useful for testing).
func ResetSchemaValidator() {
	schemaValidatorOnce = sync.Once{}
	schemaValidatorInstance = nil
}

// load loads and compiles all schemas (both lenient and strict variants).
func (v *SchemaValidator) load() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Lenient compiler — schemas as authored.
	compiler := newCompiler()
	if err := registerEmbeddedSchemas(compiler, false); err != nil {
		return fmt.Errorf("failed to register schemas: %w", err)
	}

	core, err := compiler.Compile(coreSchemaID)
	if err != nil {
		return fmt.Errorf("failed to compile core schema: %w", err)
	}
	v.coreSchema = core

	master, err := compiler.Compile(masterSchemaID)
	if err != nil {
		return fmt.Errorf("failed to compile master schema: %w", err)
	}
	v.masterSchema = master

	if err = v.compileTypeSchemas(compiler); err != nil {
		return fmt.Errorf("failed to compile type schemas: %w", err)
	}

	// Strict compiler — x-recommended promoted to required.
	strictCompiler := newCompiler()
	if err = registerEmbeddedSchemas(strictCompiler, true); err != nil {
		return fmt.Errorf("failed to register strict schemas: %w", err)
	}
	strictMaster, err := strictCompiler.Compile(masterSchemaID)
	if err != nil {
		return fmt.Errorf("failed to compile strict master schema: %w", err)
	}
	v.strictMaster = strictMaster

	v.loaded = true
	return nil
}

// newCompiler returns a Draft 2020-12 compiler.
func newCompiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	return c
}

// registerEmbeddedSchemas registers all embedded schemas with the compiler.
// When transformStrict is true, each schema is rewritten so that every
// `x-recommended` property is added to its `required` list.
func registerEmbeddedSchemas(compiler *jsonschema.Compiler, transformStrict bool) error {
	add := func(name string) error {
		data, err := schemas.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", name, err)
		}
		if transformStrict {
			data, err = transformSchemaForStrict(data)
			if err != nil {
				return fmt.Errorf("failed to transform %s: %w", name, err)
			}
		}
		// Register under the schema's $id (full URL) so $refs resolve.
		id := schemaResourceID(data, name)
		if err := compiler.AddResource(id, strings.NewReader(string(data))); err != nil {
			return fmt.Errorf("failed to add %s: %w", name, err)
		}
		return nil
	}

	if err := add("xarf-core.json"); err != nil {
		return err
	}
	if err := add("xarf-v4-master.json"); err != nil {
		return err
	}

	entries, err := schemas.FS.ReadDir("types")
	if err != nil {
		return fmt.Errorf("failed to read types directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if err := add("types/" + entry.Name()); err != nil {
			// Log but continue — some schemas may have issues.
			fmt.Printf("Warning: %v\n", err)
		}
	}
	return nil
}

// schemaResourceID returns a schema's declared $id, or fallback when absent.
func schemaResourceID(data []byte, fallback string) string {
	var m map[string]interface{}
	if json.Unmarshal(data, &m) == nil {
		if id, ok := m["$id"].(string); ok && id != "" {
			return id
		}
	}
	return fallback
}

// transformSchemaForStrict rewrites a schema so that every property marked
// `x-recommended: true` is promoted to its enclosing object's `required` list.
func transformSchemaForStrict(data []byte) ([]byte, error) {
	var schema interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, err
	}
	promoteRecommendedToRequired(schema)
	return json.Marshal(schema)
}

// promoteRecommendedToRequired walks a schema node in place, adding any
// `x-recommended` property to the node's `required` array, then recurses into
// schema-relevant sub-structures. Mirrors the JavaScript implementation.
func promoteRecommendedToRequired(node interface{}) {
	switch n := node.(type) {
	case []interface{}:
		for _, item := range n {
			promoteRecommendedToRequired(item)
		}
	case map[string]interface{}:
		promoteNodeProperties(n)
		for _, key := range []string{"properties", "$defs"} {
			if dict, ok := n[key].(map[string]interface{}); ok {
				for _, child := range dict {
					promoteRecommendedToRequired(child)
				}
			}
		}
		for _, key := range []string{"allOf", "anyOf", "oneOf", "items", "if", "then", "else", "not", "additionalProperties"} {
			if child, ok := n[key]; ok {
				promoteRecommendedToRequired(child)
			}
		}
	}
}

// promoteNodeProperties adds this node's x-recommended property names to its required list.
func promoteNodeProperties(n map[string]interface{}) {
	props, ok := n["properties"].(map[string]interface{})
	if !ok {
		return
	}

	required := map[string]bool{}
	if existing, ok := n["required"].([]interface{}); ok {
		for _, r := range existing {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	}

	for name, def := range props {
		if defMap, ok := def.(map[string]interface{}); ok {
			if rec, ok := defMap["x-recommended"].(bool); ok && rec {
				required[name] = true
			}
		}
	}

	merged := make([]interface{}, 0, len(required))
	for name := range required {
		merged = append(merged, name)
	}
	n["required"] = merged
}

// compileTypeSchemas compiles all type-specific schemas (kept for callers that
// inspect individual type schemas; primary validation uses the master schema).
func (v *SchemaValidator) compileTypeSchemas(compiler *jsonschema.Compiler) error {
	entries, err := schemas.FS.ReadDir("types")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if strings.Contains(entry.Name(), "-base.json") {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".json")
		parts := strings.SplitN(name, "-", 2)
		if len(parts) != 2 {
			continue
		}
		category := parts[0]
		typeName := strings.ReplaceAll(parts[1], "-", "_")
		key := fmt.Sprintf("%s/%s", category, typeName)

		data, err := schemas.FS.ReadFile("types/" + entry.Name())
		if err != nil {
			continue
		}
		id := schemaResourceID(data, "types/"+entry.Name())
		schema, err := compiler.Compile(id)
		if err != nil {
			fmt.Printf("Warning: failed to compile %s: %v\n", entry.Name(), err)
			continue
		}
		v.typeSchemas[key] = schema
	}
	return nil
}

// IsLoaded returns true if schemas were successfully loaded.
func (v *SchemaValidator) IsLoaded() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.loaded
}

// ValidationResult contains the result of schema validation.
type ValidationResult struct {
	Valid  bool
	Errors []string
}

// Validate validates already-decoded JSON data against the master schema.
// When strict is true, x-recommended fields are treated as required.
func (v *SchemaValidator) Validate(data interface{}, strict bool) ValidationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	schema := v.masterSchema
	if strict {
		schema = v.strictMaster
	}
	if !v.loaded || schema == nil {
		return ValidationResult{Valid: false, Errors: []string{"schema validator not loaded"}}
	}
	return validateAgainstSchema(schema, data)
}

// ValidateJSON validates a JSON string against the master XARF schema.
func (v *SchemaValidator) ValidateJSON(jsonStr string) ValidationResult {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("invalid JSON: %v", err)}}
	}
	return v.Validate(data, false)
}

// ValidateReport validates a Report struct against the master XARF schema.
func (v *SchemaValidator) ValidateReport(report interface{}) ValidationResult {
	jsonBytes, err := json.Marshal(report)
	if err != nil {
		return ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("failed to marshal report: %v", err)}}
	}
	var data interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("failed to unmarshal report: %v", err)}}
	}
	return v.Validate(data, false)
}

// validateAgainstSchema validates data against a compiled schema.
func validateAgainstSchema(schema *jsonschema.Schema, data interface{}) ValidationResult {
	err := schema.Validate(data)
	if err == nil {
		return ValidationResult{Valid: true}
	}

	var errors []string
	if validationErr, ok := err.(*jsonschema.ValidationError); ok {
		errors = dedupeStrings(extractValidationErrors(validationErr))
	} else {
		errors = []string{err.Error()}
	}
	return ValidationResult{Valid: false, Errors: errors}
}

// extractValidationErrors recursively extracts leaf error messages.
func extractValidationErrors(err *jsonschema.ValidationError) []string {
	var errors []string

	// Only emit leaf messages (causes) to avoid noisy intermediate wrappers,
	// but keep this node's message when it has no causes.
	if len(err.Causes) == 0 && err.Message != "" {
		path := err.InstanceLocation
		if path == "" {
			path = "/"
		}
		errors = append(errors, fmt.Sprintf("%s: %s", path, err.Message))
	}
	for _, cause := range err.Causes {
		errors = append(errors, extractValidationErrors(cause)...)
	}
	return errors
}

// dedupeStrings removes duplicate strings while preserving order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
