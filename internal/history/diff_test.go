package history

import (
	"testing"

	"github.com/drag-team/netvex-go/internal/model"
)

func TestDiffClassifiesEveryChange(t *testing.T) {
	snapshot := func(status model.Status, median float64) Snapshot {
		return Snapshot{Endpoint: "e", Protocol: model.ProtocolHTTP, Status: status, MedianMS: median}
	}
	base := map[string]Snapshot{
		"died": snapshot(model.StatusOK, 100), "revived": snapshot(model.StatusFailed, 0),
		"slower": snapshot(model.StatusOK, 100), "faster": snapshot(model.StatusOK, 300),
		"steady": snapshot(model.StatusOK, 100), "dead": snapshot(model.StatusTimeout, 0), "gone": snapshot(model.StatusOK, 100),
	}
	current := map[string]Snapshot{
		"died": snapshot(model.StatusTimeout, 0), "revived": snapshot(model.StatusOK, 90),
		"slower": snapshot(model.StatusOK, 200), "faster": snapshot(model.StatusOK, 100),
		"steady": snapshot(model.StatusOK, 110), "dead": snapshot(model.StatusFailed, 0), "new": snapshot(model.StatusOK, 50),
	}
	report := Diff(base, current, 50)
	for _, change := range []Change{ChangeDied, ChangeRevived, ChangeSlower, ChangeFaster, ChangeAdded, ChangeRemoved} {
		if report.Counts[change] != 1 {
			t.Fatalf("%s=%d report=%+v", change, report.Counts[change], report)
		}
	}
	if report.Unchanged != 2 || len(report.Entries) != 6 || report.Entries[0].Change != ChangeDied {
		t.Fatalf("report=%+v", report)
	}
	if empty := Diff(nil, nil, 50); empty.Unchanged != 0 || len(empty.Entries) != 0 {
		t.Fatalf("empty=%+v", empty)
	}
}
