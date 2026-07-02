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
	"strings"

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

// IgnoreList suppresses user-selected keys from drift reporting.
// Patterns have the form "kind:key"; a key ending in '*' matches by
// prefix. Kinds are the Change.Kind values (sysctl, cmdline, kconfig,
// module, mitigation, securityfs, kernel).
type IgnoreList struct {
	exact  map[string]bool     // "kind:key"
	prefix map[string][]string // kind -> key prefixes
}

var validKinds = map[string]bool{
	"sysctl": true, "cmdline": true, "kconfig": true, "module": true,
	"mitigation": true, "securityfs": true, "kernel": true,
}

// ParseIgnores builds an IgnoreList from "kind:key" patterns, rejecting
// malformed or unknown-kind patterns so typos fail loudly instead of
// silently masking real drift.
func ParseIgnores(patterns []string) (*IgnoreList, error) {
	il := &IgnoreList{exact: map[string]bool{}, prefix: map[string][]string{}}
	for _, p := range patterns {
		kind, key, ok := strings.Cut(p, ":")
		if !ok || key == "" {
			return nil, fmt.Errorf("ignore pattern %q: want kind:key (e.g. sysctl:net.netfilter.*)", p)
		}
		if !validKinds[kind] {
			return nil, fmt.Errorf("ignore pattern %q: unknown kind %q", p, kind)
		}
		if strings.HasSuffix(key, "*") {
			il.prefix[kind] = append(il.prefix[kind], strings.TrimSuffix(key, "*"))
		} else {
			il.exact[kind+":"+key] = true
		}
	}
	return il, nil
}

func (il *IgnoreList) matches(kind, key string) bool {
	if il == nil {
		return false
	}
	if il.exact[kind+":"+key] {
		return true
	}
	for _, pre := range il.prefix[kind] {
		if strings.HasPrefix(key, pre) {
			return true
		}
	}
	return false
}

// Diff computes drift from old (baseline) to new (current). ignore may
// be nil; volatile runtime counters are always suppressed regardless.
func Diff(old, cur *facts.Facts, ignore *IgnoreList) *Drift {
	d := &Drift{
		BaselineAt: old.CollectedAt.Format("2006-01-02T15:04:05Z07:00"),
		CurrentAt:  cur.CollectedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	skip := func(kind string) func(string) bool {
		return func(key string) bool { return ignore.matches(kind, key) }
	}
	d.Changes = append(d.Changes, diffMaps("sysctl", old.Sysctl, cur.Sysctl, isVolatileSysctl, skip("sysctl"))...)
	d.Changes = append(d.Changes, diffMaps("cmdline", old.Cmdline, cur.Cmdline, skip("cmdline"))...)
	d.Changes = append(d.Changes, diffMaps("kconfig", old.Kconfig, cur.Kconfig, skip("kconfig"))...)
	d.Changes = append(d.Changes, diffMaps("mitigation", old.Mitigations, cur.Mitigations, skip("mitigation"))...)
	d.Changes = append(d.Changes, diffMaps("securityfs", old.SecurityFS, cur.SecurityFS, skip("securityfs"))...)
	d.Changes = append(d.Changes, diffSets("module", old.Modules, cur.Modules, skip("module"))...)
	if old.Kernel.Release != cur.Kernel.Release && !ignore.matches("kernel", "release") {
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

// isVolatileSysctl filters runtime counters and per-boot identifiers
// that change without any configuration action. A baseline must survive
// normal operation and reboots; these keys drift by design and would
// make every diff noisy.
func isVolatileSysctl(key string) bool {
	// fs.quota.* are all counters (cache_hits, drops, lookups, reads,
	// writes, allocated_dquots, free_dquots, syncs).
	if strings.HasPrefix(key, "fs.quota.") {
		return true
	}
	switch key {
	case "fs.dentry-state", // cache occupancy counters
		"fs.file-nr",  // open file handles
		"fs.inode-nr", // inode counters
		"fs.inode-state",
		"kernel.ns_last_pid",               // last allocated PID
		"kernel.pty.nr",                    // open pseudoterminals
		"kernel.random.uuid",               // new value on every read
		"kernel.random.boot_id",            // new value every boot
		"kernel.random.entropy_avail",      // fluctuates constantly
		"net.netfilter.nf_conntrack_count": // live connection count
		return true
	default:
		return false
	}
}

func diffSets(kind string, old, cur []string, skip ...func(string) bool) []Change {
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
		if !cs[m] && !shouldSkip(m, skip) {
			out = append(out, Change{Kind: kind, Key: m, Type: "removed"})
		}
	}
	for m := range cs {
		if !os_[m] && !shouldSkip(m, skip) {
			out = append(out, Change{Kind: kind, Key: m, Type: "added"})
		}
	}
	return out
}
