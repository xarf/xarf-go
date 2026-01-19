// Package schemas provides embedded XARF JSON schemas for validation.
package schemas

import "embed"

// FS contains all embedded XARF v4 JSON schemas.
// This includes:
// - xarf-core.json: Core schema with base field definitions
// - xarf-v4-master.json: Master schema for full validation
// - types/*.json: Category-specific type schemas
//
//go:embed xarf-core.json xarf-v4-master.json types/*.json
var FS embed.FS
