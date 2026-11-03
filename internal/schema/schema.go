// Package schema derives JSON Schema documents from the result model, so the
// published contract cannot drift from what the program actually writes.
package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/drag-team/netvex-go/internal/model"
)

const dialect = "https://json-schema.org/draft/2020-12/schema"

var enums = map[reflect.Type][]string{
	reflect.TypeFor[model.Status]():   {"ok", "failed", "timeout", "auth_failed", "policy_blocked", "invalid", "inconclusive", "unreliable", "interrupted"},
	reflect.TypeFor[model.Stage]():    {"input", "resolve", "connect", "proxy_tls", "negotiate", "tunnel", "tls", "request", "response", "policy", "complete"},
	reflect.TypeFor[model.Protocol](): {"auto", "http", "https", "socks4", "socks4a", "socks5"},
}

// Documents lists every published schema by command argument.
func Documents() map[string]any {
	return map[string]any{"result": model.Result{}, "summary": model.RunSummary{}}
}

// Generate renders the named schema as indented JSON.
func Generate(name string) ([]byte, error) {
	value, ok := Documents()[name]
	if !ok {
		return nil, fmt.Errorf("unknown schema %q; available: result, summary", name)
	}
	document := describe(reflect.TypeOf(value))
	document["$schema"] = dialect
	document["$id"] = fmt.Sprintf("https://github.com/drag-team/netvex-go/blob/main/docs/schemas/%s.v%d.schema.json", name, model.SchemaVersion)
	document["title"] = fmt.Sprintf("NetVex %s, schema version %d", name, model.SchemaVersion)
	return json.MarshalIndent(document, "", "  ")
}

var timeType = reflect.TypeFor[time.Time]()

func describe(kind reflect.Type) map[string]any {
	if values, ok := enums[kind]; ok {
		return map[string]any{"type": "string", "enum": values}
	}
	if kind == timeType {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch kind.Kind() {
	case reflect.Pointer:
		return describe(kind.Elem())
	case reflect.Struct:
		return describeStruct(kind)
	case reflect.Slice:
		return map[string]any{"type": "array", "items": describe(kind.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": describe(kind.Elem())}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Float64:
		return map[string]any{"type": "number"}
	default:
		panic("schema: unsupported type " + kind.String())
	}
}

func describeStruct(kind reflect.Type) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for index := range kind.NumField() {
		field := kind.Field(index)
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" || name == "" {
			continue
		}
		properties[name] = describe(field.Type)
		if !strings.Contains(options, "omitempty") {
			required = append(required, name)
		}
	}
	// Readers are told to tolerate unknown fields, so the schema does too.
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": true}
}
