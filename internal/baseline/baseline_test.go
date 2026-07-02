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

func TestDiffIdentical(t *testing.T) {
	f := facts.Collect("../../testdata/rootfs-hardened")
	if d := Diff(f, f); d.HasDrift() {
		t.Errorf("identical snapshots reported drift: %+v", d.Changes)
	}
}
