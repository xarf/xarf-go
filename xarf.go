// Package xarf provides parsing, validation, and generation of XARF v4
// (eXtended Abuse Reporting Format) reports.
//
// The package-level Parse, CreateReport, and CreateEvidence functions mirror the
// behaviour of the official JavaScript library (@xarf/xarf): Parse returns a
// result carrying validation errors and warnings rather than failing, v3 reports
// are auto-detected and converted, and validation is schema-driven against the
// embedded v4.2.0 schemas.
package xarf

import (
	"crypto/md5"  //nolint:gosec // md5 offered only for evidence hashing parity with the JS API
	"crypto/sha1" //nolint:gosec // sha1 offered only for evidence hashing parity with the JS API
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/xarf/xarf-go/schemas"
)

// ValidationInfo describes a missing optional or recommended field.
// Mirrors the JavaScript ValidationInfo type.
type ValidationInfo struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ParseOptions controls Parse behaviour. Mirrors the JavaScript ParseOptions.
type ParseOptions struct {
	// Strict reports warnings (e.g. unknown fields) and x-recommended fields as errors.
	Strict bool
	// ShowMissingOptional populates Info with missing optional/recommended fields.
	ShowMissingOptional bool
	// MaxInputBytes, when > 0, rejects inputs larger than this many bytes before
	// JSON decoding. Zero means no limit (matching the JavaScript default).
	MaxInputBytes int
}

// ParseResult is the result of Parse. Mirrors the JavaScript ParseResult.
type ParseResult struct {
	Report   map[string]interface{} `json:"report"`
	Errors   []string               `json:"errors"`
	Warnings []string               `json:"warnings"`
	Info     []ValidationInfo       `json:"info,omitempty"`
}

// CreateReportOptions controls CreateReport behaviour.
type CreateReportOptions struct {
	Strict              bool
	ShowMissingOptional bool
}

// CreateReportResult is the result of CreateReport.
type CreateReportResult struct {
	Report   map[string]interface{} `json:"report"`
	Errors   []string               `json:"errors"`
	Warnings []string               `json:"warnings"`
	Info     []ValidationInfo       `json:"info,omitempty"`
}

// EvidenceOptions controls CreateEvidence behaviour. Mirrors the JavaScript EvidenceOptions.
type EvidenceOptions struct {
	Description string
	// HashAlgorithm is one of "sha256" (default), "sha512", "sha1", "md5".
	HashAlgorithm string
}

// Parse parses and validates a XARF report from JSON bytes.
//
// It mirrors the JavaScript parse(): v3 reports are auto-detected and converted
// (with a deprecation warning), validation is schema-driven, and validation
// failures are returned in Result.Errors rather than as an error. An error is
// returned only for malformed JSON or input exceeding MaxInputBytes.
func Parse(data []byte, options *ParseOptions) (ParseResult, error) {
	opts := ParseOptions{}
	if options != nil {
		opts = *options
	}

	if opts.MaxInputBytes > 0 && len(data) > opts.MaxInputBytes {
		return ParseResult{}, NewParseError(
			fmt.Sprintf("input exceeds maxInputBytes (%d > %d bytes)", len(data), opts.MaxInputBytes), nil)
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return ParseResult{}, NewParseError("invalid JSON", err)
	}

	warnings := []string{}

	// v3 detection and conversion.
	if IsXARFv3(obj) {
		converted, err := ConvertV3toV4(obj, &warnings)
		if err != nil {
			return ParseResult{}, err
		}
		warnings = append([]string{GetV3DeprecationWarning()}, warnings...)
		obj = converted
	}

	errors, fieldWarnings, info := validateData(obj, opts.Strict, opts.ShowMissingOptional)
	warnings = append(warnings, fieldWarnings...)

	// In strict mode, validateData has already folded warnings into errors.
	if opts.Strict {
		warnings = nil
	}

	result := ParseResult{Report: obj, Errors: errors, Warnings: warnings}
	if opts.ShowMissingOptional {
		result.Info = info
	}
	return result, nil
}

// ParseString parses and validates a XARF report from a JSON string.
func ParseString(jsonStr string, options *ParseOptions) (ParseResult, error) {
	return Parse([]byte(jsonStr), options)
}

// CreateReport builds a validated XARF report from input, auto-filling
// xarf_version, report_id, and timestamp when absent. Mirrors the JavaScript
// createReport(): the assembled report is always returned alongside any
// validation errors/warnings.
func CreateReport(input map[string]interface{}, options *CreateReportOptions) CreateReportResult {
	opts := CreateReportOptions{}
	if options != nil {
		opts = *options
	}

	report := make(map[string]interface{}, len(input)+3)
	for k, v := range input {
		report[k] = v
	}
	report["xarf_version"] = SpecVersion
	if id, ok := report["report_id"].(string); !ok || id == "" {
		report["report_id"] = NewGenerator().GenerateUUID()
	}
	if ts, ok := report["timestamp"].(string); !ok || ts == "" {
		report["timestamp"] = NewGenerator().GenerateTimestamp()
	}

	errors, warnings, info := validateData(report, opts.Strict, opts.ShowMissingOptional)
	if opts.Strict {
		warnings = nil
	}

	result := CreateReportResult{Report: report, Errors: errors, Warnings: warnings}
	if opts.ShowMissingOptional {
		result.Info = info
	}
	return result
}

// CreateEvidence builds an evidence item with base64-encoded payload, an
// algorithm-prefixed hash ("sha256:<hex>"), and a byte size. Mirrors the
// JavaScript createEvidence().
func CreateEvidence(contentType string, payload []byte, options *EvidenceOptions) Evidence {
	algorithm := "sha256"
	description := ""
	if options != nil {
		if options.HashAlgorithm != "" {
			algorithm = options.HashAlgorithm
		}
		description = options.Description
	}

	hashValue := computeHash(algorithm, payload)

	return Evidence{
		ContentType: contentType,
		Description: description,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Hash:        fmt.Sprintf("%s:%s", algorithm, hashValue),
		Size:        len(payload),
	}
}

// computeHash returns the hex digest of data for the named algorithm.
// Unknown algorithms fall back to sha256, matching the JS default.
func computeHash(algorithm string, data []byte) string {
	switch algorithm {
	case "sha512":
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum(data) //nolint:gosec // parity with JS evidence hashing options
		return hex.EncodeToString(sum[:])
	case "md5":
		sum := md5.Sum(data) //nolint:gosec // parity with JS evidence hashing options
		return hex.EncodeToString(sum[:])
	default: // sha256
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
}

// validateData runs the full JS-equivalent validation pipeline on a decoded
// report object: schema validation, unknown-field warnings, strict promotion of
// warnings to errors, and (optionally) missing-optional info.
func validateData(data map[string]interface{}, strict, showMissingOptional bool) (errors, warnings []string, info []ValidationInfo) {
	res := GetSchemaValidator().Validate(data, strict)
	if !res.Valid {
		errors = append(errors, res.Errors...)
	}

	warnings = collectUnknownFields(data)

	if strict && len(warnings) > 0 {
		errors = append(errors, warnings...)
		warnings = nil
	}

	if showMissingOptional {
		info = collectMissingOptionalFields(data)
	}
	return errors, warnings, info
}

// collectUnknownFields returns a warning for every top-level field of data that
// is not defined by the core schema or the matched type schema.
func collectUnknownFields(data map[string]interface{}) []string {
	reg := GetSchemaRegistry()
	known := collectSchemaPropertyNames(reg.GetCoreSchema())

	if cat, ok := data["category"].(string); ok && cat != "" {
		if typ, ok := data["type"].(string); ok && typ != "" {
			for name := range collectSchemaPropertyNames(reg.GetTypeSchema(Category(cat), typ)) {
				known[name] = true
			}
		}
	}

	var warnings []string
	for _, field := range sortedKeys(data) {
		if !known[field] {
			warnings = append(warnings, fmt.Sprintf(
				"%s: Unknown field '%s' is not defined in the XARF schema", field, field))
		}
	}
	return warnings
}

type optionalField struct {
	description string
	recommended bool
}

// collectMissingOptionalFields returns info entries for optional/recommended
// fields (from the core and matched type schemas) absent from data.
func collectMissingOptionalFields(data map[string]interface{}) []ValidationInfo {
	reg := GetSchemaRegistry()
	optional := extractOptionalFields(reg.GetCoreSchema())

	if cat, ok := data["category"].(string); ok && cat != "" {
		if typ, ok := data["type"].(string); ok && typ != "" {
			for name, of := range extractOptionalFields(reg.GetTypeSchema(Category(cat), typ)) {
				optional[name] = of
			}
		}
	}

	names := make([]string, 0, len(optional))
	for name := range optional {
		names = append(names, name)
	}
	sort.Strings(names)

	var info []ValidationInfo
	for _, name := range names {
		if _, present := data[name]; present {
			continue
		}
		prefix := "OPTIONAL"
		if optional[name].recommended {
			prefix = "RECOMMENDED"
		}
		info = append(info, ValidationInfo{Field: name, Message: fmt.Sprintf("%s: %s", prefix, optional[name].description)})
	}
	return info
}

// collectSchemaPropertyNames recursively gathers every property name declared by
// a schema, including via allOf/anyOf/oneOf and "-base.json" $refs.
func collectSchemaPropertyNames(schema map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	walkSchemaProperties(schema, out)
	return out
}

func walkSchemaProperties(node interface{}, out map[string]bool) {
	switch n := node.(type) {
	case []interface{}:
		for _, item := range n {
			walkSchemaProperties(item, out)
		}
	case map[string]interface{}:
		collectMapProperties(n, out)
	}
}

func collectMapProperties(n map[string]interface{}, out map[string]bool) {
	if props, ok := n["properties"].(map[string]interface{}); ok {
		for name := range props {
			out[name] = true
		}
	}
	if ref, ok := n["$ref"].(string); ok && strings.Contains(ref, "-base.json") {
		if base := loadBaseSchemaMap(ref); base != nil {
			walkSchemaProperties(base, out)
		}
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		if arr, ok := n[key].([]interface{}); ok {
			for _, item := range arr {
				walkSchemaProperties(item, out)
			}
		}
	}
}

// extractOptionalFields gathers optional (non-required, non-_internal) fields and
// whether each is x-recommended, recursing into allOf/"-base.json" refs.
func extractOptionalFields(schema map[string]interface{}) map[string]optionalField {
	out := map[string]optionalField{}
	if schema != nil {
		walkOptionalFields(schema, out)
	}
	return out
}

func walkOptionalFields(node map[string]interface{}, out map[string]optionalField) {
	addOptionalProps(node, requiredSet(node), out)
	walkOptionalAllOf(node, out)
}

func requiredSet(node map[string]interface{}) map[string]bool {
	set := map[string]bool{}
	if req, ok := node["required"].([]interface{}); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				set[s] = true
			}
		}
	}
	return set
}

func addOptionalProps(node map[string]interface{}, required map[string]bool, out map[string]optionalField) {
	props, ok := node["properties"].(map[string]interface{})
	if !ok {
		return
	}
	for name, def := range props {
		if required[name] || name == "_internal" {
			continue
		}
		out[name] = optionalFieldFromDef(name, def)
	}
}

func optionalFieldFromDef(name string, def interface{}) optionalField {
	defMap, _ := def.(map[string]interface{})
	desc, _ := defMap["description"].(string)
	if desc == "" {
		desc = "Optional field: " + name
	}
	recommended, _ := defMap["x-recommended"].(bool)
	return optionalField{description: desc, recommended: recommended}
}

func walkOptionalAllOf(node map[string]interface{}, out map[string]optionalField) {
	arr, ok := node["allOf"].([]interface{})
	if !ok {
		return
	}
	for _, item := range arr {
		sub, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if ref, ok := sub["$ref"].(string); ok {
			if base := loadBaseSchemaMap(ref); base != nil {
				walkOptionalFields(base, out)
			}
			continue
		}
		walkOptionalFields(sub, out)
	}
}

// loadBaseSchemaMap loads a "-base.json" schema referenced by $ref from the
// embedded schemas (base schemas live under types/).
func loadBaseSchemaMap(ref string) map[string]interface{} {
	filename := ref
	for strings.HasPrefix(filename, "./") || strings.HasPrefix(filename, "../") {
		filename = strings.TrimPrefix(filename, "./")
		filename = strings.TrimPrefix(filename, "../")
	}
	data, err := schemas.FS.ReadFile("types/" + filename)
	if err != nil {
		return nil
	}
	var out map[string]interface{}
	if json.Unmarshal(data, &out) != nil {
		return nil
	}
	return out
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
