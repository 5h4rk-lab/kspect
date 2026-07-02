// Package baseline persists fact snapshots and computes configuration
// drift between a saved baseline and the current system state.
//
// Drift detection is the fleet/CI use case: capture a known-good posture
// once, then fail pipelines or alert when a node deviates (a sysctl
// silently reset by a package upgrade, an unexpected module loaded, a
// changed boot parameter).
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/5h4rk-lab/kspect/internal/facts"
)

// Change describes one drifted key.
type Change struct {
	Kind string `json:"kind"` // sysctl | cmdline | kconfig | module | mitigation | securityfs | kernel
	Key  string `json:"key"`
	Old  string `json:"old,omitempty"`
	New  string `json:"new,omitempty"`
	Type string `json:"type"` // added | removed | changed
}

// Drift is the result of comparing two snapshots.
type Drift struct {
	BaselineAt string   `json:"baseline_collected_at"`
	CurrentAt  string   `json:"current_collected_at"`
	Changes    []Change `json:"changes"`
}

// HasDrift reports whether any change was detected.
func (d *Drift) HasDrift() bool { return len(d.Changes) > 0 }

// Save writes a facts snapshot to path with restrictive permissions
// (snapshots contain host configuration detail).
func Save(f *facts.Facts, path string) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Load reads a snapshot from path.
func Load(path string) (*facts.Facts, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f facts.Facts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: not a kspect baseline: %w", path, err)
	}
	return &f, nil
}

// Diff computes drift from old (baseline) to new (current).
func Diff(old, cur *facts.Facts) *Drift {
	d := &Drift{
		BaselineAt: old.CollectedAt.Format("2006-01-02T15:04:05Z07:00"),
		CurrentAt:  cur.CollectedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	d.Changes = append(d.Changes, diffMaps("sysctl", old.Sysctl, cur.Sysctl, isVolatileSysctl)...)
	d.Changes = append(d.Changes, diffMaps("cmdline", old.Cmdline, cur.Cmdline)...)
	d.Changes = append(d.Changes, diffMaps("kconfig", old.Kconfig, cur.Kconfig)...)
	d.Changes = append(d.Changes, diffMaps("mitigation", old.Mitigations, cur.Mitigations)...)
	d.Changes = append(d.Changes, diffMaps("securityfs", old.SecurityFS, cur.SecurityFS)...)
	d.Changes = append(d.Changes, diffSets("module", old.Modules, cur.Modules)...)
	if old.Kernel.Release != cur.Kernel.Release {
		d.Changes = append(d.Changes, Change{
			Kind: "kernel", Key: "release",
			Old: old.Kernel.Release, New: cur.Kernel.Release, Type: "changed",
		})
	}
	sort.SliceStable(d.Changes, func(i, j int) bool {
		if d.Changes[i].Kind != d.Changes[j].Kind {
			return d.Changes[i].Kind < d.Changes[j].Kind
		}
		return d.Changes[i].Key < d.Changes[j].Key
	})
	return d
}

func diffMaps(kind string, old, cur map[string]string, skip ...func(string) bool) []Change {
	// If either side failed to collect this source entirely, do not
	// report the whole source as removed/added — that would be pure noise.
	if len(old) == 0 || len(cur) == 0 {
		return nil
	}
	var out []Change
	for k, ov := range old {
		if shouldSkip(k, skip) {
			continue
		}
		nv, ok := cur[k]
		switch {
		case !ok:
			out = append(out, Change{Kind: kind, Key: k, Old: ov, Type: "removed"})
		case nv != ov:
			out = append(out, Change{Kind: kind, Key: k, Old: ov, New: nv, Type: "changed"})
		}
	}
	for k, nv := range cur {
		if shouldSkip(k, skip) {
			continue
		}
		if _, ok := old[k]; !ok {
			out = append(out, Change{Kind: kind, Key: k, New: nv, Type: "added"})
		}
	}
	return out
}

func shouldSkip(key string, skip []func(string) bool) bool {
	for _, fn := range skip {
		if fn != nil && fn(key) {
			return true
		}
	}
	return false
}

func isVolatileSysctl(key string) bool {
	switch key {
	case "fs.dentry-state",
		"fs.file-nr",
		"fs.inode-nr",
		"fs.inode-state",
		"fs.quota.cache_hits",
		"fs.quota.drops",
		"fs.quota.lookups",
		"kernel.ns_last_pid",
		"kernel.random.uuid":
		return true
	default:
		return false
	}
}

func diffSets(kind string, old, cur []string) []Change {
	if old == nil || cur == nil {
		return nil
	}
	os_ := map[string]bool{}
	cs := map[string]bool{}
	for _, m := range old {
		os_[m] = true
	}
	for _, m := range cur {
		cs[m] = true
	}
	var out []Change
	for m := range os_ {
		if !cs[m] {
			out = append(out, Change{Kind: kind, Key: m, Type: "removed"})
		}
	}
	for m := range cs {
		if !os_[m] {
			out = append(out, Change{Kind: kind, Key: m, Type: "added"})
		}
	}
	return out
}
