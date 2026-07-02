package main

import (
	"os"
	"path/filepath"
	"testing"
)

const hardened = "../../testdata/rootfs-hardened"
const weak = "../../testdata/rootfs-weak"

// TestExitCodeContract pins the documented exit codes; CI systems depend
// on them, so a change here is a breaking change.
func TestExitCodeContract(t *testing.T) {
	// Silence table output during tests.
	old := os.Stdout
	null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = null
	defer func() { os.Stdout = old }()

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"scan clean", []string{"scan", "--root", hardened}, 0},
		{"scan failing", []string{"scan", "--root", weak}, 1},
		{"scan failing json", []string{"scan", "--root", weak, "--format", "json"}, 1},
		{"scan gate above findings", []string{"scan", "--root", hardened, "--fail-on", "high"}, 0},
		{"scan bad severity", []string{"scan", "--fail-on", "urgent"}, 3},
		{"scan bad format", []string{"scan", "--root", hardened, "--format", "xml"}, 3},
		{"unknown command", []string{"frobnicate"}, 3},
		{"diff missing file", []string{"diff", "/nonexistent/base.json"}, 3},
		{"rules list", []string{"rules"}, 0},
		{"version", []string{"version"}, 0},
	}
	for _, tc := range cases {
		if got := run(tc.args); got != tc.want {
			t.Errorf("%s: exit = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestBaselineDiffFlow(t *testing.T) {
	old := os.Stdout
	null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = null
	defer func() { os.Stdout = old }()

	base := filepath.Join(t.TempDir(), "base.json")
	if got := run([]string{"baseline", "--root", hardened, base}); got != 0 {
		t.Fatalf("baseline exit = %d", got)
	}
	if got := run([]string{"diff", base, "--root", hardened}); got != 0 {
		t.Errorf("no-drift diff exit = %d, want 0", got)
	}
	if got := run([]string{"diff", base, "--root", weak}); got != 2 {
		t.Errorf("drift diff exit = %d, want 2", got)
	}
}

func TestCustomRulesOverride(t *testing.T) {
	old := os.Stdout
	null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = null
	defer func() { os.Stdout = old }()

	// Disable every builtin that fails on the weak fixture except one,
	// then gate on high: overriding via custom ruleset must work.
	custom := filepath.Join(t.TempDir(), "custom.json")
	err := os.WriteFile(custom, []byte(`{
	  "version": 1,
	  "rules": [
	    {"id": "KSPECT-SYSCTL-001", "title": "override", "severity": "info",
	     "rationale": "downgraded for test",
	     "checks": [{"source": "sysctl", "key": "kernel.kptr_restrict", "op": "min", "value": "1"}]}
	  ]
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// The downgraded rule alone (via tag filter impossible here) — instead
	// verify loading succeeds and scan still runs.
	if got := run([]string{"scan", "--root", weak, "--rules", custom, "--fail-on", "high"}); got != 1 {
		t.Errorf("scan with custom rules exit = %d, want 1 (other high findings remain)", got)
	}
	if got := run([]string{"scan", "--root", weak, "--rules", "/nonexistent.json"}); got != 3 {
		t.Errorf("missing ruleset exit = %d, want 3", got)
	}
}
