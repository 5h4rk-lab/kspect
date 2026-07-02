package engine

import (
	"testing"

	"github.com/5h4rk-lab/kspect/internal/facts"
	"github.com/5h4rk-lab/kspect/internal/rules"
)

func evaluateFixture(t *testing.T, root string) map[string]Finding {
	t.Helper()
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	rep := Evaluate(facts.Collect(root), rs)
	out := map[string]Finding{}
	for _, f := range rep.Findings {
		out[f.RuleID] = f
	}
	return out
}

func TestHardenedFixtureHasNoRealFailures(t *testing.T) {
	rs, _ := rules.LoadBuiltin()
	rep := Evaluate(facts.Collect("../../testdata/rootfs-hardened"), rs)
	for _, f := range rep.Findings {
		if f.Status == Fail && f.Severity != rules.SevInfo {
			t.Errorf("hardened fixture failed %s (%s): observed %s", f.RuleID, f.Severity, f.Observed)
		}
		if f.Status == Unknown {
			t.Errorf("hardened fixture should have no unknowns, got %s", f.RuleID)
		}
	}
}

func TestWeakFixtureFindings(t *testing.T) {
	got := evaluateFixture(t, "../../testdata/rootfs-weak")

	expectFail := []string{
		"KSPECT-SYSCTL-001",  // kptr_restrict=0
		"KSPECT-SYSCTL-003",  // unprivileged bpf enabled
		"KSPECT-SYSCTL-009",  // ASLR off
		"KSPECT-CMDLINE-001", // mitigations=off
		"KSPECT-CMDLINE-002", // nokaslr
		"KSPECT-CMDLINE-003", // nosmep present (match=all)
		"KSPECT-MITIG-001",   // Vulnerable entries
		"KSPECT-LSM-001",     // no major LSM
		"KSPECT-MODULE-001",  // dccp loaded
		"KSPECT-MODULE-003",  // tipc loaded
		"KSPECT-SYSCTL-024",  // ipv6 redirects accepted
	}
	for _, id := range expectFail {
		if f, ok := got[id]; !ok || f.Status != Fail {
			t.Errorf("%s: want Fail, got %+v", id, f.Status)
		}
	}

	expectUnknown := []string{
		"KSPECT-KCONFIG-001",  // no kernel config on fixture
		"KSPECT-SYSCTL-018",   // io_uring_disabled key absent (old kernel)
		"KSPECT-LOCKDOWN-001", // no lockdown file
	}
	for _, id := range expectUnknown {
		if f, ok := got[id]; !ok || f.Status != Unknown {
			t.Errorf("%s: want Unknown (never a fabricated Fail), got %v", id, f.Status)
		}
	}

	// Modules that are absent must pass, not fail.
	if f := got["KSPECT-MODULE-002"]; f.Status != Pass {
		t.Errorf("rds not loaded should Pass, got %v", f.Status)
	}
	// cmdline: nopti absent -> pass
	if f := got["KSPECT-CMDLINE-004"]; f.Status != Pass {
		t.Errorf("nopti absent should Pass, got %v", f.Status)
	}

	// MITIG-001 must name the vulnerable entries for actionability.
	if f := got["KSPECT-MITIG-001"]; f.Status == Fail {
		if want := "meltdown"; !contains(f.Observed, want) {
			t.Errorf("mitigation finding should name vulnerable entry, got %q", f.Observed)
		}
	}
}

func TestMatchAllSemantics(t *testing.T) {
	f := &facts.Facts{
		Cmdline:    map[string]string{"nosmep": ""},
		CmdlineRaw: "nosmep",
	}
	r := rules.Rule{
		ID: "T", Severity: rules.SevHigh, Match: "all",
		Checks: []rules.Check{
			{Source: rules.SrcCmdline, Key: "nosmep", Op: rules.OpAbsent},
			{Source: rules.SrcCmdline, Key: "nosmap", Op: rules.OpAbsent},
		},
	}
	rep := Evaluate(f, []rules.Rule{r})
	if rep.Findings[0].Status != Fail {
		t.Errorf("match=all with one failing check must Fail, got %v", rep.Findings[0].Status)
	}

	// any-of: same checks, default match — one passing check suffices.
	r.Match = ""
	rep = Evaluate(f, []rules.Rule{r})
	if rep.Findings[0].Status != Pass {
		t.Errorf("match=any with one passing check must Pass, got %v", rep.Findings[0].Status)
	}
}

func TestUnknownWhenSourceUnavailable(t *testing.T) {
	f := &facts.Facts{} // nothing collected
	r := rules.Rule{
		ID: "T", Severity: rules.SevHigh,
		Checks: []rules.Check{{Source: rules.SrcSysctl, Key: "kernel.kptr_restrict", Op: rules.OpMin, Value: "1"}},
	}
	rep := Evaluate(f, []rules.Rule{r})
	if rep.Findings[0].Status != Unknown {
		t.Errorf("missing data source must yield Unknown, got %v", rep.Findings[0].Status)
	}
	if rep.Summary.Fail != 0 {
		t.Error("unknowns must never count as failures")
	}
}

func TestNumericComparisonToleratesMultiValueSysctl(t *testing.T) {
	f := &facts.Facts{Sysctl: map[string]string{"kernel.printk": "4\t4\t1\t7"}}
	r := rules.Rule{
		ID: "T", Severity: rules.SevLow,
		Checks: []rules.Check{{Source: rules.SrcSysctl, Key: "kernel.printk", Op: rules.OpMin, Value: "4"}},
	}
	rep := Evaluate(f, []rules.Rule{r})
	if rep.Findings[0].Status != Pass {
		t.Errorf("first-token numeric parse failed: %+v", rep.Findings[0])
	}
}

func TestDisabledRulesSkipped(t *testing.T) {
	f := &facts.Facts{Sysctl: map[string]string{"k": "0"}}
	r := rules.Rule{
		ID: "T", Severity: rules.SevHigh, Disabled: true,
		Checks: []rules.Check{{Source: rules.SrcSysctl, Key: "k", Op: rules.OpEquals, Value: "1"}},
	}
	rep := Evaluate(f, []rules.Rule{r})
	if rep.Summary.Total != 0 {
		t.Error("disabled rule was evaluated")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
