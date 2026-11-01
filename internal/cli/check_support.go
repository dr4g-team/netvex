package cli

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/dr4g-team/netvex/internal/store"
)

// identityKey loads the secret behind credential-scoped result IDs on first use,
// so runs without credentials never touch the data directory. If it cannot be
// stored, IDs fall back to this process: resume then revalidates instead of
// wrongly skipping proxies.
func (c CLI) identityKey(dataDir string) func() []byte {
	return sync.OnceValue(func() []byte {
		key, err := store.LoadIdentityKey(dataDir)
		if err == nil {
			return key
		}
		fmt.Fprintln(c.Stderr, "warning: credential identity key is not persistent:", err)
		return store.EphemeralIdentityKey()
	})
}

func recommendedConcurrency() int {
	recommended := runtime.NumCPU() * 64
	if recommended < 32 {
		recommended = 32
	}
	if soft, _, available := fileDescriptorLimit(); available {
		fileBound := int(min(soft/4, 1<<30)) - 32
		if fileBound > 0 && recommended > fileBound {
			recommended = fileBound
		}
	}
	if recommended > 1024 {
		recommended = 1024
	}
	return recommended
}

// prescreenReservedDescriptors keeps room for validation sockets, output files,
// and resolver traffic when the prescreen stage is sized against the limit.
const prescreenReservedDescriptors = 128

func boundedPrescreenWorkers(requested, validationWorkers int) int {
	soft, _, available := fileDescriptorLimit()
	if !available {
		return requested
	}
	reserve := uint64(validationWorkers) + prescreenReservedDescriptors
	if soft <= reserve {
		return 1
	}
	return int(min(uint64(requested), soft-reserve))
}

func topCounts(counts map[string]int, limit int) string {
	type item struct {
		name  string
		count int
	}
	items := make([]item, 0, len(counts))
	for name, count := range counts {
		items = append(items, item{name, count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, len(items))
	for i, x := range items {
		parts[i] = fmt.Sprintf("%s:%d", x.name, x.count)
	}
	return strings.Join(parts, ",")
}
