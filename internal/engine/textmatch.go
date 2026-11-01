package engine

import (
	"bytes"
	"strings"
)

type textMatchPlan struct {
	patterns  []textPattern
	maxLength int
}

type textPattern struct {
	value  []byte
	anchor int
}

type textMatcher struct {
	plan      *textMatchPlan
	found     []bool
	remaining int
	tail      []byte
	boundary  []byte
}

func compileTextMatchPlan(required, rejected []string) *textMatchPlan {
	patterns := append(append([]string{}, required...), rejected...)
	if len(patterns) == 0 {
		return nil
	}
	for _, pattern := range patterns {
		if pattern == "" {
			return nil
		}
		for index := range len(pattern) {
			if pattern[index] >= 0x80 {
				return nil
			}
		}
	}
	plan := &textMatchPlan{patterns: make([]textPattern, len(patterns))}
	for index, pattern := range patterns {
		value := []byte(pattern)
		plan.patterns[index] = textPattern{value: value, anchor: textPatternAnchor(value)}
		if len(pattern) > plan.maxLength {
			plan.maxLength = len(pattern)
		}
	}
	return plan
}

func (p *textMatchPlan) matcher() *textMatcher {
	if p == nil {
		return nil
	}
	return &textMatcher{plan: p, found: make([]bool, len(p.patterns)), remaining: len(p.patterns), tail: make([]byte, 0, p.maxLength-1)}
}

func (m *textMatcher) Write(value []byte) (int, error) {
	if len(value) == 0 || m.remaining == 0 {
		return len(value), nil
	}
	tailLength := m.plan.maxLength - 1
	boundaryLength := 0
	if len(m.tail) > 0 && tailLength > 0 {
		boundaryLength = len(m.tail) + min(len(value), tailLength)
		if cap(m.boundary) < boundaryLength {
			m.boundary = make([]byte, boundaryLength)
		} else {
			m.boundary = m.boundary[:boundaryLength]
		}
		copy(m.boundary, m.tail)
		copy(m.boundary[len(m.tail):], value[:boundaryLength-len(m.tail)])
	}
	for index, pattern := range m.plan.patterns {
		if !m.found[index] && (containsASCIIFold(value, pattern) || boundaryLength > 0 && containsASCIIFold(m.boundary, pattern)) {
			m.found[index] = true
			m.remaining--
		}
	}
	if m.remaining == 0 || tailLength == 0 {
		m.tail = m.tail[:0]
		return len(value), nil
	}
	if len(value) >= tailLength {
		m.tail = append(m.tail[:0], value[len(value)-tailLength:]...)
	} else if boundaryLength == 0 {
		m.tail = append(m.tail[:0], value...)
	} else {
		keep := min(tailLength, boundaryLength)
		m.tail = append(m.tail[:0], m.boundary[boundaryLength-keep:]...)
	}
	return len(value), nil
}

func textPatternAnchor(pattern []byte) int {
	// Prefer a less common ASCII byte when possible. The matcher only uses the
	// anchor to locate candidates; EqualFold still verifies the full pattern.
	best, bestRank := 0, 0
	for index, value := range pattern {
		rank := strings.IndexByte("etaoinshrdlucmfwypvbgkjqxz", asciiLower(value))
		if rank > bestRank {
			best, bestRank = index, rank
		}
	}
	return best
}

func containsASCIIFold(data []byte, pattern textPattern) bool {
	anchor := pattern.value[pattern.anchor]
	if containsAnchoredFold(data, pattern.value, pattern.anchor, anchor) {
		return true
	}
	upper := anchor
	if anchor >= 'a' && anchor <= 'z' {
		upper = anchor - ('a' - 'A')
	}
	return upper != anchor && containsAnchoredFold(data, pattern.value, pattern.anchor, upper)
}

func containsAnchoredFold(data, pattern []byte, anchor int, character byte) bool {
	for offset := 0; offset < len(data); {
		index := bytes.IndexByte(data[offset:], character)
		if index < 0 {
			return false
		}
		position := offset + index
		start := position - anchor
		if start >= 0 && start+len(pattern) <= len(data) && bytes.EqualFold(data[start:start+len(pattern)], pattern) {
			return true
		}
		offset = position + 1
	}
	return false
}

func asciiLower(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}
