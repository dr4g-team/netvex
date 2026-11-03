package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/drag-team/netvex-go/internal/model"
)

// publishedSchemas fails when docs/schemas falls behind the model. Regenerate with:
// go run ./cmd/netvex schema result > docs/schemas/result.vN.schema.json
func TestPublishedSchemasMatchTheModel(t *testing.T) {
	for name := range Documents() {
		generated, err := Generate(name)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("..", "..", "docs", "schemas", fmt.Sprintf("%s.v%d.schema.json", name, model.SchemaVersion))
		published, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(published)) != string(generated) {
			t.Fatalf("%s is stale; regenerate it with netvex schema %s", path, name)
		}
	}
}

func TestSchemaCoversEveryField(t *testing.T) {
	var result map[string]any
	generated, err := Generate("result")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(generated, &result); err != nil {
		t.Fatal(err)
	}
	properties := result["properties"].(map[string]any)
	kind := reflect.TypeFor[model.Result]()
	for index := range kind.NumField() {
		name, _, _ := strings.Cut(kind.Field(index).Tag.Get("json"), ",")
		if name == "-" {
			if _, leaked := properties[kind.Field(index).Name]; leaked {
				t.Fatal("credential-bearing field reached the schema")
			}
			continue
		}
		if _, ok := properties[name]; !ok {
			t.Fatalf("field %s is missing", name)
		}
	}
	status := properties["status"].(map[string]any)
	if len(status["enum"].([]any)) != 9 {
		t.Fatalf("status=%v", status)
	}
	checked := properties["checked_at"].(map[string]any)
	if checked["format"] != "date-time" {
		t.Fatalf("checked_at=%v", checked)
	}
}

// A real result must satisfy every structural claim the schema makes.
func TestSampleResultSatisfiesSchema(t *testing.T) {
	value := 88.5
	sample := model.Result{SchemaVersion: model.SchemaVersion, ID: "abc", Proxy: "http://h:1", Endpoint: "h:1", Protocol: model.ProtocolHTTP, Status: model.StatusOK, Attempts: 1, Successes: 1, RequiredSuccesses: 1,
		Observations: []model.Observation{{Attempt: 1, StartedAt: time.Now().UTC(), Protocol: model.ProtocolHTTP, Target: "t", Status: model.StatusOK, Stage: model.StageComplete, Timings: model.Timings{TotalMS: 1, QueueMS: 2}, ExitIP: "1.2.3.4", ResponseHeaders: map[string]string{"Server": "x"}, Metadata: &model.ExitMetadata{Country: "x"}}},
		Rotation:     model.RotationProfile{Classification: "unavailable"}, Score: model.Score{Value: &value, Confidence: "low", Reason: "r"}, Capabilities: &model.Capabilities{ExitIPv4: true}, CheckedAt: time.Now().UTC()}
	payload, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	var instance any
	if err := json.Unmarshal(payload, &instance); err != nil {
		t.Fatal(err)
	}
	generated, err := Generate("result")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(generated, &document); err != nil {
		t.Fatal(err)
	}
	validate(t, "result", document, instance)
}

// validate implements the small JSON Schema subset that Generate emits.
func validate(t *testing.T, path string, schema map[string]any, value any) {
	t.Helper()
	if allowed, ok := schema["enum"].([]any); ok {
		found := false
		for _, option := range allowed {
			found = found || option == value
		}
		if !found {
			t.Fatalf("%s: %v is outside the enum", path, value)
		}
	}
	switch schema["type"] {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%s: %T is not an object", path, value)
		}
		if required, ok := schema["required"].([]any); ok {
			for _, name := range required {
				if _, present := object[name.(string)]; !present {
					t.Fatalf("%s: missing required %s", path, name)
				}
			}
		}
		properties, _ := schema["properties"].(map[string]any)
		additional, _ := schema["additionalProperties"].(map[string]any)
		for name, item := range object {
			if property, ok := properties[name].(map[string]any); ok {
				validate(t, path+"."+name, property, item)
			} else if additional != nil {
				validate(t, path+"."+name, additional, item)
			}
		}
	case "array":
		list, ok := value.([]any)
		if !ok {
			t.Fatalf("%s: %T is not an array", path, value)
		}
		for index, item := range list {
			validate(t, fmt.Sprintf("%s[%d]", path, index), schema["items"].(map[string]any), item)
		}
	case "string":
		if _, ok := value.(string); !ok {
			t.Fatalf("%s: %T is not a string", path, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			t.Fatalf("%s: %T is not a boolean", path, value)
		}
	case "integer", "number":
		if _, ok := value.(float64); !ok {
			t.Fatalf("%s: %T is not a number", path, value)
		}
	}
}
