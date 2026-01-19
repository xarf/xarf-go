package xarf

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/xarf/xarf-go/schemas"
)

// SchemaValidator validates XARF reports against JSON schemas.
type SchemaValidator struct {
	compiler    *jsonschema.Compiler
	coreSchema  *jsonschema.Schema
	typeSchemas map[string]*jsonschema.Schema // key: "category/type"
	loaded      bool
	mu          sync.RWMutex
}

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

// load loads and compiles all schemas.
func (v *SchemaValidator) load() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Create compiler with custom loader for embedded schemas
	v.compiler = jsonschema.NewCompiler()
	v.compiler.Draft = jsonschema.Draft2020

	// Register embedded schemas
	if err := v.registerEmbeddedSchemas(); err != nil {
		return fmt.Errorf("failed to register schemas: %w", err)
	}

	// Compile core schema
	coreSchema, err := v.compiler.Compile("xarf-core.json")
	if err != nil {
		return fmt.Errorf("failed to compile core schema: %w", err)
	}
	v.coreSchema = coreSchema

	// Compile type schemas
	if err := v.compileTypeSchemas(); err != nil {
		return fmt.Errorf("failed to compile type schemas: %w", err)
	}

	v.loaded = true
	return nil
}

// registerEmbeddedSchemas registers all embedded schemas with the compiler.
func (v *SchemaValidator) registerEmbeddedSchemas() error {
	// Register core schema
	coreData, err := schemas.FS.ReadFile("xarf-core.json")
	if err != nil {
		return fmt.Errorf("failed to read xarf-core.json: %w", err)
	}
	if addErr := v.compiler.AddResource("xarf-core.json", strings.NewReader(string(coreData))); addErr != nil {
		return fmt.Errorf("failed to add xarf-core.json: %w", addErr)
	}

	// Register master schema
	masterData, err := schemas.FS.ReadFile("xarf-v4-master.json")
	if err != nil {
		return fmt.Errorf("failed to read xarf-v4-master.json: %w", err)
	}
	if addErr := v.compiler.AddResource("xarf-v4-master.json", strings.NewReader(string(masterData))); addErr != nil {
		return fmt.Errorf("failed to add xarf-v4-master.json: %w", addErr)
	}

	// Register type schemas
	entries, err := schemas.FS.ReadDir("types")
	if err != nil {
		return fmt.Errorf("failed to read types directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := schemas.FS.ReadFile("types/" + entry.Name())
		if err != nil {
			continue
		}

		resourceName := "types/" + entry.Name()
		if err := v.compiler.AddResource(resourceName, strings.NewReader(string(data))); err != nil {
			// Log but continue - some schemas may have issues
			fmt.Printf("Warning: failed to add %s: %v\n", resourceName, err)
		}
	}

	return nil
}

// compileTypeSchemas compiles all type-specific schemas.
func (v *SchemaValidator) compileTypeSchemas() error {
	entries, err := schemas.FS.ReadDir("types")
	if err != nil {
		return err
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

		category := parts[0]
		typeName := strings.ReplaceAll(parts[1], "-", "_")
		key := fmt.Sprintf("%s/%s", category, typeName)

		resourceName := "types/" + entry.Name()
		schema, err := v.compiler.Compile(resourceName)
		if err != nil {
			// Log but continue
			fmt.Printf("Warning: failed to compile %s: %v\n", resourceName, err)
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

// ValidateJSON validates a JSON string against the core XARF schema.
func (v *SchemaValidator) ValidateJSON(jsonStr string) ValidationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.loaded || v.coreSchema == nil {
		return ValidationResult{
			Valid:  false,
			Errors: []string{"schema validator not loaded"},
		}
	}

	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("invalid JSON: %v", err)},
		}
	}

	return v.validateAgainstSchema(v.coreSchema, data)
}

// ValidateReport validates a Report struct against the appropriate schema.
func (v *SchemaValidator) ValidateReport(report interface{}) ValidationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.loaded {
		return ValidationResult{
			Valid:  false,
			Errors: []string{"schema validator not loaded"},
		}
	}

	// Convert report to JSON then to interface{}
	jsonBytes, err := json.Marshal(report)
	if err != nil {
		return ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("failed to marshal report: %v", err)},
		}
	}

	var data interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("failed to unmarshal report: %v", err)},
		}
	}

	// First validate against core schema
	result := v.validateAgainstSchema(v.coreSchema, data)
	if !result.Valid {
		return result
	}

	// Then validate against type-specific schema if available
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return result
	}

	category, _ := dataMap["category"].(string)
	typeName, _ := dataMap["type"].(string)

	if category != "" && typeName != "" {
		key := fmt.Sprintf("%s/%s", category, typeName)
		if typeSchema, exists := v.typeSchemas[key]; exists {
			typeResult := v.validateAgainstSchema(typeSchema, data)
			if !typeResult.Valid {
				return typeResult
			}
		}
	}

	return result
}

// validateAgainstSchema validates data against a compiled schema.
func (v *SchemaValidator) validateAgainstSchema(schema *jsonschema.Schema, data interface{}) ValidationResult {
	err := schema.Validate(data)
	if err == nil {
		return ValidationResult{Valid: true}
	}

	// Extract validation errors
	var errors []string
	if validationErr, ok := err.(*jsonschema.ValidationError); ok {
		errors = extractValidationErrors(validationErr)
	} else {
		errors = []string{err.Error()}
	}

	return ValidationResult{
		Valid:  false,
		Errors: errors,
	}
}

// extractValidationErrors recursively extracts error messages from validation errors.
func extractValidationErrors(err *jsonschema.ValidationError) []string {
	var errors []string

	if err.Message != "" {
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
