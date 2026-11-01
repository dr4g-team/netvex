package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/drag-team/netvex/internal/config"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/protocol"
)

type jsonExpectation struct {
	path     []string
	expected string
}

type compiledResponseRules struct {
	minHTTPStatus     int
	maxHTTPStatus     int
	minResponseBytes  int64
	minThroughputKBPS float64
	requireText       []string
	rejectText        []string
	expectJSON        []jsonExpectation
	expectedBodySHA   string
	textPlan          *textMatchPlan
}

func compileResponseRules(rules config.ResponseRules) compiledResponseRules {
	compiled := compiledResponseRules{
		minHTTPStatus: rules.MinHTTPStatus, maxHTTPStatus: rules.MaxHTTPStatus,
		minResponseBytes: rules.MinResponseBytes, minThroughputKBPS: rules.MinThroughputKBPS,
		expectedBodySHA: strings.ToLower(rules.ExpectedBodySHA),
	}
	for _, rule := range rules.RequireText {
		compiled.requireText = append(compiled.requireText, strings.ToLower(rule))
	}
	for _, rule := range rules.RejectText {
		compiled.rejectText = append(compiled.rejectText, strings.ToLower(rule))
	}
	for _, rule := range rules.ExpectJSON {
		path, expected, _ := strings.Cut(rule, "=")
		compiled.expectJSON = append(compiled.expectJSON, jsonExpectation{path: strings.Split(path, "."), expected: expected})
	}
	return compiled
}

func (c *Checker) buildRules(target string) compiledResponseRules {
	rules := compiledResponseRules{
		minHTTPStatus: 200, maxHTTPStatus: 399,
		minResponseBytes: c.Config.MinResponseBytes, minThroughputKBPS: c.Config.MinThroughputKBPS,
		requireText: c.requireText, rejectText: c.rejectText, expectJSON: c.expectJSON,
		expectedBodySHA: strings.ToLower(c.Config.ExpectedBodySHA),
	}
	if targetRules, ok := c.targetRules[target]; ok {
		if targetRules.minHTTPStatus > 0 {
			rules.minHTTPStatus = targetRules.minHTTPStatus
		}
		if targetRules.maxHTTPStatus > 0 {
			rules.maxHTTPStatus = targetRules.maxHTTPStatus
		}
		if targetRules.minResponseBytes > 0 {
			rules.minResponseBytes = targetRules.minResponseBytes
		}
		if targetRules.minThroughputKBPS > 0 {
			rules.minThroughputKBPS = targetRules.minThroughputKBPS
		}
		if targetRules.expectedBodySHA != "" {
			rules.expectedBodySHA = targetRules.expectedBodySHA
		}
		rules.requireText = append(append([]string{}, rules.requireText...), targetRules.requireText...)
		rules.rejectText = append(append([]string{}, rules.rejectText...), targetRules.rejectText...)
		rules.expectJSON = append(append([]jsonExpectation{}, rules.expectJSON...), targetRules.expectJSON...)
	}
	rules.textPlan = compileTextMatchPlan(rules.requireText, rules.rejectText)
	return rules
}

func (c *Checker) rulesFor(target string) compiledResponseRules {
	if rules, ok := c.effectiveRules[target]; ok {
		return rules
	}
	return c.buildRules(target)
}

func checkTextRules(headers http.Header, body []byte, bodyMatcher *textMatcher, rules compiledResponseRules) error {
	if len(rules.requireText) == 0 && len(rules.rejectText) == 0 {
		return nil
	}
	var headerText strings.Builder
	headerText.Grow(1024)
	for name, values := range headers {
		headerText.WriteByte('\n')
		headerText.WriteString(strings.ToLower(name))
		headerText.WriteByte(':')
		headerText.WriteString(strings.ToLower(strings.Join(values, ",")))
	}
	headersLower := headerText.String()
	var headerMatches []bool
	if rules.textPlan != nil {
		headerMatcher := rules.textPlan.matcher()
		_, _ = headerMatcher.Write([]byte(headersLower))
		headerMatches = headerMatcher.found
	}
	var bodyLower []byte
	if rules.textPlan == nil {
		bodyLower = bytes.ToLower(body)
	}
	for i, required := range rules.requireText {
		matched := rules.textPlan != nil && (bodyMatcher.found[i] || headerMatches[i])
		if rules.textPlan == nil {
			matched = bytes.Contains(bodyLower, []byte(required)) || strings.Contains(headersLower, required)
		}
		if !matched {
			return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "required_content_missing", Detail: fmt.Sprintf("response did not satisfy required content rule %d", i+1)}
		}
	}
	for i, rejected := range rules.rejectText {
		patternIndex := len(rules.requireText) + i
		matched := rules.textPlan != nil && (bodyMatcher.found[patternIndex] || headerMatches[patternIndex])
		if rules.textPlan == nil {
			matched = bytes.Contains(bodyLower, []byte(rejected)) || strings.Contains(headersLower, rejected)
		}
		if matched {
			return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "rejected_content_present", Detail: fmt.Sprintf("response matched rejected content rule %d", i+1)}
		}
	}
	return nil
}

func checkJSONRules(body []byte, rules compiledResponseRules) error {
	if len(rules.expectJSON) == 0 {
		return nil
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	decodeErr := decoder.Decode(&document)
	var trailing any
	if decodeErr != nil || decoder.Decode(&trailing) != io.EOF {
		return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "expected_json_invalid", Detail: "response is not valid JSON required by configured assertions"}
	}
	for i, expectation := range rules.expectJSON {
		value, found := jsonPath(document, expectation.path)
		if !found || fmt.Sprint(value) != expectation.expected {
			return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "json_assertion_failed", Detail: fmt.Sprintf("response did not satisfy JSON assertion %d", i+1)}
		}
	}
	return nil
}
