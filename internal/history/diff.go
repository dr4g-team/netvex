package history

import (
	"sort"

	"github.com/dr4g-team/netvex/internal/model"
)

type Change string

const (
	ChangeDied    Change = "died"
	ChangeRevived Change = "revived"
	ChangeAdded   Change = "added"
	ChangeRemoved Change = "removed"
	ChangeSlower  Change = "slower"
	ChangeFaster  Change = "faster"
)

// Snapshot is the part of a result that a run comparison needs.
type Snapshot struct {
	Endpoint string
	Protocol model.Protocol
	Status   model.Status
	MedianMS float64
}

type DiffEntry struct {
	ID              string         `json:"id"`
	Endpoint        string         `json:"endpoint"`
	Protocol        model.Protocol `json:"protocol"`
	Change          Change         `json:"change"`
	BaseStatus      model.Status   `json:"base_status,omitempty"`
	CurrentStatus   model.Status   `json:"current_status,omitempty"`
	BaseMedianMS    float64        `json:"base_median_ms,omitempty"`
	CurrentMedianMS float64        `json:"current_median_ms,omitempty"`
}

type DiffReport struct {
	Counts    map[Change]int `json:"counts"`
	Unchanged int            `json:"unchanged"`
	Truncated bool           `json:"truncated,omitempty"`
	Entries   []DiffEntry    `json:"entries"`
}

// Diff classifies each proxy between two runs. Latency only counts when a proxy
// worked in both, because a median from a failed proxy describes nothing.
func Diff(base, current map[string]Snapshot, latencyChangePercent float64) DiffReport {
	report := DiffReport{Counts: map[Change]int{}, Entries: []DiffEntry{}}
	record := func(id string, change Change, before, after Snapshot) {
		endpoint, protocol := after.Endpoint, after.Protocol
		if endpoint == "" {
			endpoint, protocol = before.Endpoint, before.Protocol
		}
		report.Counts[change]++
		report.Entries = append(report.Entries, DiffEntry{ID: id, Endpoint: endpoint, Protocol: protocol, Change: change, BaseStatus: before.Status, CurrentStatus: after.Status, BaseMedianMS: before.MedianMS, CurrentMedianMS: after.MedianMS})
	}
	for id, after := range current {
		before, existed := base[id]
		wasOK, isOK := before.Status == model.StatusOK, after.Status == model.StatusOK
		switch {
		case !existed:
			record(id, ChangeAdded, Snapshot{}, after)
		case wasOK && !isOK:
			record(id, ChangeDied, before, after)
		case !wasOK && isOK:
			record(id, ChangeRevived, before, after)
		case wasOK && isOK && before.MedianMS > 0 && after.MedianMS >= before.MedianMS*(1+latencyChangePercent/100):
			record(id, ChangeSlower, before, after)
		case wasOK && isOK && before.MedianMS > 0 && after.MedianMS <= before.MedianMS/(1+latencyChangePercent/100):
			record(id, ChangeFaster, before, after)
		default:
			report.Unchanged++
		}
	}
	for id, before := range base {
		if _, stillThere := current[id]; !stillThere {
			record(id, ChangeRemoved, before, Snapshot{})
		}
	}
	rank := map[Change]int{ChangeDied: 0, ChangeRevived: 1, ChangeSlower: 2, ChangeFaster: 3, ChangeAdded: 4, ChangeRemoved: 5}
	sort.Slice(report.Entries, func(i, j int) bool {
		left, right := report.Entries[i], report.Entries[j]
		if left.Change != right.Change {
			return rank[left.Change] < rank[right.Change]
		}
		return left.Endpoint < right.Endpoint
	})
	return report
}
