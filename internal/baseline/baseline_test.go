package baseline

import (
	"path/filepath"
	"testing"

	"github.com/5h4rk-lab/kspect/internal/facts"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	f := facts.Collect("../../testdata/rootfs-hardened")
	path := filepath.Join(t.TempDir(), "base.json")
	if err := Save(f, path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kernel.Release != f.Kernel.Release || len(got.Sysctl) != len(f.Sysctl) {
		t.Error("roundtrip lost data")
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := Save(&facts.Facts{}, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDiffDetectsChanges(t *testing.T) {
	old := &facts.Facts{
		Sysctl:  map[string]string{"a": "1", "b": "2", "gone": "x"},
		Cmdline: map[string]string{"quiet": ""},
		Modules: []string{"ext4"},
		Kernel:  facts.Kernel{Release: "6.8.0"},
	}
	cur := &facts.Facts{
		Sysctl:  map[string]string{"a": "1", "b": "3", "new": "y"},
		Cmdline: map[string]string{"quiet": ""},
		Modules: []string{"ext4", "dccp"},
		Kernel:  facts.Kernel{Release: "6.9.0"},
	}
	d := Diff(old, cur)
	if !d.HasDrift() {
		t.Fatal("expected drift")
	}
	types := map[string]int{}
	for _, c := range d.Changes {
		types[c.Kind+"/"+c.Type]++
	}
	for _, want := range []string{"sysctl/changed", "sysctl/added", "sysctl/removed", "module/added", "kernel/changed"} {
		if types[want] == 0 {
			t.Errorf("missing change %s in %v", want, types)
		}
	}
}

func TestDiffNoNoiseWhenSourceMissing(t *testing.T) {
	// A source that failed to collect on one side must not spam
	// added/removed changes for every key.
	old := &facts.Facts{Sysctl: map[string]string{"a": "1"}, Kconfig: map[string]string{"CONFIG_X": "y"}}
	cur := &facts.Facts{Sysctl: map[string]string{"a": "1"}} // kconfig unavailable now
	d := Diff(old, cur)
	for _, c := range d.Changes {
		if c.Kind == "kconfig" {
			t.Errorf("kconfig drift reported despite missing source: %+v", c)
		}
	}
}

func TestDiffIgnoresVolatileSysctls(t *testing.T) {
	old := &facts.Facts{Sysctl: map[string]string{
		"fs.dentry-state":      "76099\t67205\t45\t0\t6485\t0",
		"fs.file-nr":           "1630\t0\t9223372036854775807",
		"fs.inode-nr":          "69602\t569",
		"fs.inode-state":       "69602\t569\t0\t0\t0\t0\t0",
		"fs.quota.cache_hits":  "682",
		"fs.quota.drops":       "637",
		"fs.quota.lookups":     "684",
		"kernel.kptr_restrict": "2",
		"kernel.ns_last_pid":   "6451",
		"kernel.random.uuid":   "fa1cc13b-c574-47ae-8504-9611518f2760",
	}}
	cur := &facts.Facts{Sysctl: map[string]string{
		"fs.dentry-state":      "76100\t67206\t45\t0\t6485\t0",
		"fs.file-nr":           "1631\t0\t9223372036854775807",
		"fs.inode-nr":          "69603\t569",
		"fs.inode-state":       "69603\t569\t0\t0\t0\t0\t0",
		"fs.quota.cache_hits":  "686",
		"fs.quota.drops":       "641",
		"fs.quota.lookups":     "688",
		"kernel.kptr_restrict": "0",
		"kernel.ns_last_pid":   "6456",
		"kernel.random.uuid":   "2b59aab8-7e41-46a8-b596-2b9ab5e847da",
	}}
	d := Diff(old, cur)
	if len(d.Changes) != 1 {
		t.Fatalf("changes = %+v, want only stable sysctl drift", d.Changes)
	}
	got := d.Changes[0]
	if got.Kind != "sysctl" || got.Key != "kernel.kptr_restrict" || got.Type != "changed" {
		t.Fatalf("change = %+v, want kernel.kptr_restrict drift", got)
	}
}

func TestDiffIdentical(t *testing.T) {
	f := facts.Collect("../../testdata/rootfs-hardened")
	if d := Diff(f, f); d.HasDrift() {
		t.Errorf("identical snapshots reported drift: %+v", d.Changes)
	}
}
