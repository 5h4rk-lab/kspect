// Package rules defines the policy-as-code rule model and loads rulesets.
//
// Rules are plain JSON (not YAML) so the tool stays dependency-free and
// rulesets remain trivially machine-generated and diffable. The builtin
// ruleset is embedded in the binary; users can layer their own rules on
// top with --rules, overriding builtins by ID (set "disabled": true to
// silence a builtin).
package rules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

//go:embed builtin.json
var builtinJSON []byte

// Severity of a rule. Ordered for threshold comparisons.
type Severity string

const (
	SevInfo   Severity = "info"
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

var sevRank = map[Severity]int{SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3}

// Rank returns the numeric ordering of a severity (-1 if unknown).
func (s Severity) Rank() int {
	if r, ok := sevRank[s]; ok {
		return r
	}
	return -1
}

// ParseSeverity validates a user-supplied severity string.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(s)
	if sev.Rank() < 0 {
		return "", fmt.Errorf("invalid severity %q (want info|low|medium|high)", s)
	}
	return sev, nil
}

// Source identifies which fact collection a rule inspects.
type Source string

const (
	SrcSysctl     Source = "sysctl"
	SrcKconfig    Source = "kconfig"
	SrcCmdline    Source = "cmdline"
	SrcModule     Source = "module"
	SrcMitigation Source = "mitigation"
	SrcSecurityFS Source = "securityfs"
)

// Op is the comparison applied to the observed value.
type Op string

const (
	OpEquals      Op = "equals"
	OpNotEquals   Op = "not_equals"
	OpOneOf       Op = "one_of"
	OpContains    Op = "contains"
	OpNotContains Op = "not_contains"
	OpPresent     Op = "present"
	OpAbsent      Op = "absent"
	OpMin         Op = "min" // numeric: observed >= value
	OpMax         Op = "max" // numeric: observed <= value
)

var validOps = map[Op]bool{
	OpEquals: true, OpNotEquals: true, OpOneOf: true, OpContains: true,
	OpNotContains: true, OpPresent: true, OpAbsent: true, OpMin: true, OpMax: true,
}

// Check is a single condition against one fact source.
type Check struct {
	Source Source   `json:"source"`
	Key    string   `json:"key"`
	Op     Op       `json:"op"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"` // for one_of
}

// Rule is one auditable statement about kernel security posture.
//
// Match semantics ("any" by default): with "any", a rule passes if ANY
// check passes — this models equivalent controls (e.g. "vsyscall disabled
// via kconfig OR via boot parameter"). With "all", every evaluable check
// must pass — this models conjunctions ("neither nosmep nor nosmap set").
// No full expression language is provided on purpose: two combinators
// cover the real-world rules while keeping rulesets auditable.
type Rule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Match       string   `json:"match,omitempty"` // "any" (default) | "all"
	Tags        []string `json:"tags,omitempty"`
	Rationale   string   `json:"rationale"`
	Remediation string   `json:"remediation,omitempty"`
	Refs        []string `json:"refs,omitempty"`
	Checks      []Check  `json:"checks"`
	Disabled    bool     `json:"disabled,omitempty"`
}

type ruleFile struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

// LoadBuiltin returns the embedded default ruleset.
func LoadBuiltin() ([]Rule, error) {
	return parse(builtinJSON)
}

// LoadFile loads a user ruleset from disk.
func LoadFile(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs, err := parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rs, nil
}

func parse(b []byte) ([]Rule, error) {
	var rf ruleFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("parse ruleset: %w", err)
	}
	if rf.Version != 1 {
		return nil, fmt.Errorf("unsupported ruleset version %d (want 1)", rf.Version)
	}
	if err := Validate(rf.Rules); err != nil {
		return nil, err
	}
	return rf.Rules, nil
}

// Validate enforces schema invariants so bad rules fail fast at load time
// instead of producing silently-wrong scan results.
func Validate(rs []Rule) error {
	seen := map[string]bool{}
	for _, r := range rs {
		if r.ID == "" {
			return fmt.Errorf("rule with empty id (title: %q)", r.Title)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Severity.Rank() < 0 {
			return fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
		}
		if len(r.Checks) == 0 {
			return fmt.Errorf("rule %s: no checks", r.ID)
		}
		if r.Match != "" && r.Match != "any" && r.Match != "all" {
			return fmt.Errorf("rule %s: invalid match %q (want any|all)", r.ID, r.Match)
		}
		for i, c := range r.Checks {
			if !validOps[c.Op] {
				return fmt.Errorf("rule %s check %d: invalid op %q", r.ID, i, c.Op)
			}
			if c.Op == OpOneOf && len(c.Values) == 0 {
				return fmt.Errorf("rule %s check %d: one_of requires values", r.ID, i)
			}
			needsValue := c.Op == OpEquals || c.Op == OpNotEquals ||
				c.Op == OpContains || c.Op == OpNotContains || c.Op == OpMin || c.Op == OpMax
			if needsValue && c.Value == "" {
				return fmt.Errorf("rule %s check %d: op %s requires value", r.ID, i, c.Op)
			}
			switch c.Source {
			case SrcSysctl, SrcKconfig, SrcCmdline, SrcModule, SrcMitigation, SrcSecurityFS:
			default:
				return fmt.Errorf("rule %s check %d: invalid source %q", r.ID, i, c.Source)
			}
			if c.Key == "" && !(c.Source == SrcMitigation) {
				return fmt.Errorf("rule %s check %d: empty key", r.ID, i)
			}
		}
	}
	return nil
}

// Merge overlays custom rules on the builtin set. A custom rule with an
// existing ID replaces the builtin (allowing overrides or, with
// disabled:true, suppression). New IDs are appended. Result is sorted by
// ID for stable output.
func Merge(builtin, custom []Rule) []Rule {
	byID := map[string]Rule{}
	order := make([]string, 0, len(builtin)+len(custom))
	for _, r := range builtin {
		byID[r.ID] = r
		order = append(order, r.ID)
	}
	for _, r := range custom {
		if _, exists := byID[r.ID]; !exists {
			order = append(order, r.ID)
		}
		byID[r.ID] = r
	}
	sort.Strings(order)
	out := make([]Rule, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

// FilterTags keeps rules matching any of the requested tags. Empty tag
// list keeps everything.
func FilterTags(rs []Rule, tags []string) []Rule {
	if len(tags) == 0 {
		return rs
	}
	want := map[string]bool{}
	for _, t := range tags {
		want[t] = true
	}
	var out []Rule
	for _, r := range rs {
		for _, t := range r.Tags {
			if want[t] {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
