package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// sourceRegistry maps a cluster id to its scannable source (an offline manifest
// path or "live[:context]"). It implements dashboard.ClusterRegistrar so the
// dashboard's POST/DELETE /v1/clusters routes can add/remove sources at runtime,
// and it is read by the scanner closure for each scan. Safe for concurrent use:
// request handlers mutate it while scans read it.
type sourceRegistry struct {
	mu  sync.RWMutex
	src map[string]string
}

func newSourceRegistry() *sourceRegistry {
	return &sourceRegistry{src: map[string]string{}}
}

// AddSource registers (or replaces) a cluster's source after validating it. A
// live source is "live" or "live:<context>"; anything else is treated as an
// offline manifest path and must exist on disk, so a bad registration fails
// fast rather than surfacing only on the next scan.
func (s *sourceRegistry) AddSource(clusterID, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("source is empty")
	}
	if source != "live" && !strings.HasPrefix(source, "live:") {
		if _, err := os.Stat(source); err != nil {
			return fmt.Errorf("manifest path not found: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.src[clusterID] = source
	return nil
}

// RemoveSource deregisters a cluster's source (idempotent).
func (s *sourceRegistry) RemoveSource(clusterID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.src, clusterID)
}

// source returns the current source for a cluster, if registered.
func (s *sourceRegistry) source(clusterID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src, ok := s.src[clusterID]
	return src, ok
}

// ids returns the registered cluster ids in a stable (sorted) order, so startup
// scans and scheduler specs are deterministic regardless of map iteration.
func (s *sourceRegistry) ids() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.src))
	for id := range s.src {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
