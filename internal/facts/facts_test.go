package facts

import (
	"testing"
)

const hardened = "../../testdata/rootfs-hardened"
const weak = "../../testdata/rootfs-weak"

func TestCollectHardened(t *testing.T) {
	f := Collect(hardened)

	if got := f.Kernel.Release; got != "6.8.0-hardened" {
		t.Errorf("kernel release = %q", got)
	}
	if got := f.Sysctl["kernel.kptr_restrict"]; got != "2" {
		t.Errorf("kptr_restrict = %q, want 2", got)
	}
	if got := f.Sysctl["kernel.yama.ptrace_scope"]; got != "1" {
		t.Errorf("nested sysctl key = %q, want 1", got)
	}
	// cmdline: bare flag and key=value forms
	if _, ok := f.Cmdline["slab_nomerge"]; !ok {
		t.Error("bare cmdline flag slab_nomerge not parsed")
	}
	if got := f.Cmdline["lockdown"]; got != "integrity" {
		t.Errorf("cmdline lockdown = %q", got)
	}
	// kconfig: set, unset, source detection
	if got := f.Kconfig["CONFIG_RANDOMIZE_BASE"]; got != "y" {
		t.Errorf("CONFIG_RANDOMIZE_BASE = %q", got)
	}
	if got := f.Kconfig["CONFIG_DEVMEM"]; got != "n" {
		t.Errorf(`"is not set" option = %q, want n`, got)
	}
	if f.KconfigSource == "" {
		t.Error("kconfig source not recorded")
	}
	// modules sorted and deduped
	if len(f.Modules) != 2 || f.Modules[0] != "ext4" || f.Modules[1] != "xfs" {
		t.Errorf("modules = %v", f.Modules)
	}
	// mitigations
	if got := f.Mitigations["meltdown"]; got != "Mitigation: PTI" {
		t.Errorf("meltdown = %q", got)
	}
	// securityfs: bracketed lockdown value normalized
	if got := f.SecurityFS["lockdown"]; got != "integrity" {
		t.Errorf("lockdown = %q, want integrity", got)
	}
	if got := f.SecurityFS["lsm"]; got != "capability,landlock,lockdown,yama,apparmor" {
		t.Errorf("lsm = %q", got)
	}
}

func TestCollectWeakMissingSources(t *testing.T) {
	f := Collect(weak)
	if len(f.Kconfig) != 0 {
		t.Errorf("expected no kconfig, got %d entries", len(f.Kconfig))
	}
	if _, ok := f.SecurityFS["lockdown"]; ok {
		t.Error("lockdown should be absent on weak fixture")
	}
	if len(f.Errors) == 0 {
		t.Error("expected collection errors to be recorded for missing sources")
	}
}

func TestCollectNonexistentRoot(t *testing.T) {
	f := Collect("/nonexistent-kspect-root")
	if len(f.Sysctl) != 0 || len(f.Modules) != 0 {
		t.Error("expected empty facts for nonexistent root")
	}
	if len(f.Errors) == 0 {
		t.Error("expected errors recorded")
	}
}

func TestParseBracketed(t *testing.T) {
	cases := map[string]string{
		"none [integrity] confidentiality": "integrity",
		"[none] integrity confidentiality": "none",
		"integrity":                        "integrity",
		"":                                 "",
	}
	for in, want := range cases {
		if got := parseBracketed(in); got != want {
			t.Errorf("parseBracketed(%q) = %q, want %q", in, got, want)
		}
	}
}
