package rules

import (
	"strings"
	"testing"
)

func TestBuiltinLoadsAndValidates(t *testing.T) {
	rs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("builtin ruleset invalid: %v", err)
	}
	if len(rs) < 40 {
		t.Errorf("expected >=40 builtin rules, got %d", len(rs))
	}
	for _, r := range rs {
		if r.Rationale == "" {
			t.Errorf("rule %s has no rationale", r.ID)
		}
		if r.Severity != SevInfo && r.Remediation == "" {
			t.Errorf("rule %s has no remediation", r.ID)
		}
		if !strings.HasPrefix(r.ID, "KSPECT-") {
			t.Errorf("rule %s: IDs must be namespaced with KSPECT-", r.ID)
		}
	}
}

func TestValidateRejectsBadRules(t *testing.T) {
	bad := []struct {
		name string
		rule Rule
	}{
		{"empty id", Rule{Severity: SevLow, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpEquals, Value: "1"}}}},
		{"bad severity", Rule{ID: "X", Severity: "urgent", Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpEquals, Value: "1"}}}},
		{"no checks", Rule{ID: "X", Severity: SevLow}},
		{"bad op", Rule{ID: "X", Severity: SevLow, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: "gt", Value: "1"}}}},
		{"bad source", Rule{ID: "X", Severity: SevLow, Checks: []Check{{Source: "dmesg", Key: "k", Op: OpEquals, Value: "1"}}}},
		{"one_of without values", Rule{ID: "X", Severity: SevLow, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpOneOf}}}},
		{"missing value", Rule{ID: "X", Severity: SevLow, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpMin}}}},
		{"bad match", Rule{ID: "X", Severity: SevLow, Match: "some", Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpPresent}}}},
	}
	for _, tc := range bad {
		if err := Validate([]Rule{tc.rule}); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
	dup := Rule{ID: "X", Severity: SevLow, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpPresent}}}
	if err := Validate([]Rule{dup, dup}); err == nil {
		t.Error("duplicate IDs: expected validation error")
	}
}

func TestMergeOverridesAndAppends(t *testing.T) {
	builtin := []Rule{
		{ID: "A", Severity: SevHigh, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpPresent}}},
		{ID: "B", Severity: SevLow, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpPresent}}},
	}
	custom := []Rule{
		{ID: "A", Severity: SevLow, Disabled: true, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpPresent}}},
		{ID: "C", Severity: SevMedium, Checks: []Check{{Source: SrcSysctl, Key: "k", Op: OpPresent}}},
	}
	got := Merge(builtin, custom)
	if len(got) != 3 {
		t.Fatalf("merged len = %d, want 3", len(got))
	}
	byID := map[string]Rule{}
	for _, r := range got {
		byID[r.ID] = r
	}
	if !byID["A"].Disabled || byID["A"].Severity != SevLow {
		t.Error("custom rule did not override builtin A")
	}
	if _, ok := byID["C"]; !ok {
		t.Error("new custom rule C not appended")
	}
}

func TestFilterTags(t *testing.T) {
	rs := []Rule{
		{ID: "A", Tags: []string{"server", "network"}},
		{ID: "B", Tags: []string{"workstation"}},
	}
	got := FilterTags(rs, []string{"network"})
	if len(got) != 1 || got[0].ID != "A" {
		t.Errorf("FilterTags = %v", got)
	}
	if got := FilterTags(rs, nil); len(got) != 2 {
		t.Error("empty tag filter must keep all rules")
	}
}

func TestParseSeverity(t *testing.T) {
	if _, err := ParseSeverity("high"); err != nil {
		t.Error(err)
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("expected error for invalid severity")
	}
	if SevHigh.Rank() <= SevMedium.Rank() || SevMedium.Rank() <= SevLow.Rank() || SevLow.Rank() <= SevInfo.Rank() {
		t.Error("severity ordering broken")
	}
}
