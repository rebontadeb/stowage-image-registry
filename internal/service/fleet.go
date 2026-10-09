package service

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/rdeb/local-image-registry/internal/runtime"
)

const usageTTL = time.Minute

type usageEntry struct {
	bytes   int64
	ok      bool
	at      time.Time
	loading bool
}

type FleetItem struct {
	View
	UsedBytes *int64 `json:"usedBytes"` // null until measured, or when the runtime cannot tell
	// From the latest vulnerability scans of this registry's images (0 when nothing was scanned).
	ScannedImages int `json:"scannedImages"`
	CriticalVulns int `json:"criticalVulns"`
	HighVulns     int `json:"highVulns"`
}

type FleetSummary struct {
	ScannedImages          int   `json:"scannedImages"`
	CriticalVulns          int   `json:"criticalVulns"`
	HighVulns              int   `json:"highVulns"`
	RegistriesWithCritical int   `json:"registriesWithCritical"`
	Total                  int   `json:"total"`
	Running                int   `json:"running"`
	Starting               int   `json:"starting"`
	Stopped                int   `json:"stopped"`
	Missing                int   `json:"missing"`
	TLS                    int   `json:"tls"`
	NoTLS                  int   `json:"noTLS"`
	UsedBytes              int64 `json:"usedBytes"`
}

// usage holds measured volume sizes. Measuring walks a volume, so it never blocks a request:
// Fleet returns the last value (nil the first time) and refreshes in the background.
type usageCache struct {
	mu sync.Mutex
	m  map[string]*usageEntry
}

func (c *usageCache) get(name string) (*usageEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*usageEntry{}
	}
	e := c.m[name]
	if e == nil {
		e = &usageEntry{}
		c.m[name] = e
	}
	stale := !e.loading && time.Since(e.at) > usageTTL
	if stale {
		e.loading = true
	}
	cp := *e
	return &cp, stale
}

func (c *usageCache) put(name string, n int64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[name] = &usageEntry{bytes: n, ok: ok, at: time.Now()}
}

func (c *usageCache) drop(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, name)
}

// Fleet lists the registries `allow` accepts with a status summary.
func (s *Service) Fleet(ctx context.Context, allow func(name string) bool) (FleetSummary, []FleetItem, error) {
	views, err := s.List(ctx)
	if err != nil {
		return FleetSummary{}, nil, err
	}
	var sum FleetSummary
	items := make([]FleetItem, 0, len(views))
	for _, v := range views {
		if !allow(v.Name) {
			continue
		}
		it := FleetItem{View: v}
		sum.Total++
		switch v.State {
		case runtime.StateRunning:
			sum.Running++
		case runtime.StateStarting:
			sum.Starting++
		case runtime.StateStopped:
			sum.Stopped++
		default:
			sum.Missing++
		}
		if v.TLS {
			sum.TLS++
		} else {
			sum.NoTLS++
		}
		e, refresh := s.usage.get(v.Name)
		if e.ok {
			n := e.bytes
			it.UsedBytes = &n
			sum.UsedBytes += n
		}
		if refresh {
			go func(name string) {
				cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				n, err := s.drv.UsedBytes(cctx, name)
				s.usage.put(name, n, err == nil)
			}(v.Name)
		}
		items = append(items, it)
	}
	s.addVulnTotals(&sum, items)
	return sum, items, nil
}

// addVulnTotals folds the latest vulnerability scans into the fleet numbers and per-registry rows.
func (s *Service) addVulnTotals(sum *FleetSummary, items []FleetItem) {
	if s.sec == nil {
		return
	}
	scans, err := s.st.ListDoneScans(KindVuln)
	if err != nil {
		return
	}
	idx := map[string]*FleetItem{}
	for i := range items {
		idx[items[i].Name] = &items[i]
	}
	crit := map[string]bool{}
	for _, sc := range scans {
		it := idx[sc.Registry]
		if it == nil {
			continue
		}
		var v struct{ Critical, High int }
		if json.Unmarshal([]byte(sc.Summary), &v) != nil {
			continue
		}
		sum.ScannedImages++
		sum.CriticalVulns += v.Critical
		sum.HighVulns += v.High
		it.ScannedImages++
		it.CriticalVulns += v.Critical
		it.HighVulns += v.High
		if v.Critical > 0 {
			crit[sc.Registry] = true
		}
	}
	sum.RegistriesWithCritical = len(crit)
}
