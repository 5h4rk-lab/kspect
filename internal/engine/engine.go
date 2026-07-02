// Package engine evaluates rules against collected facts.
//
// Design principle: never fabricate a failure. If the data source a rule
// needs is unavailable (no kernel config exposed, sysctl key doesn't exist
// on this kernel version), the result is Unknown — reported, but never a
// FAIL and never part of the CI gate by default. This is the primary
// false-positive control.
package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/5h4rk-lab/kspect/internal/facts"
	"github.com/5h4rk-lab/kspect/internal/rules"
)

// Status of a rule evaluation.
type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

// Finding is the result of evaluating one rule.
type Finding struct {
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Severity    rules.Severity `json:"severity"`
	Status      Status         `json:"status"`
	Observed    string         `json:"observed,omitempty"`
	Expected    string         `json:"expected,omitempty"`
	Rationale   string         `json:"rationale,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Refs        []string       `json:"refs,omitempty"`
}

// Summary aggregates a scan.
type Summary struct {
	Total   int `json:"total"`
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
	// FailBySeverity counts failures per severity.
	FailBySeverity map[rules.Severity]int `json:"fail_by_severity"`
}

// Report is the full scan result.
type Report struct {
	Kernel   facts.Kernel `json:"kernel"`
	Findings []Finding    `json:"findings"`
	Summary  Summary      `json:"summary"`
}

// Evaluate runs every enabled rule against the facts.
func Evaluate(f *facts.Facts, rs []rules.Rule) *Report {
	rep := &Report{
		Kernel:  f.Kernel,
		Summary: Summary{FailBySeverity: map[rules.Severity]int{}},
	}
	for _, r := range rs {
		if r.Disabled {
			continue
		}
		fd := evalRule(f, r)
		rep.Findings = append(rep.Findings, fd)
		rep.Summary.Total++
		switch fd.Status {
		case Pass:
			rep.Summary.Pass++
		case Fail:
			rep.Summary.Fail++
			rep.Summary.FailBySeverity[fd.Severity]++
		case Unknown:
			rep.Summary.Unknown++
		}
	}
	// Stable ordering: failures first (by severity desc), then unknown,
	// then passes; ties broken by rule ID.
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Status != b.Status {
			return statusRank(a.Status) < statusRank(b.Status)
		}
		if a.Severity != b.Severity {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.RuleID < b.RuleID
	})
	return rep
}

func statusRank(s Status) int {
	switch s {
	case Fail:
		return 0
	case Unknown:
		return 1
	default:
		return 2
	}
}

// evalRule combines check results according to the rule's match mode.
//
//	any (default): pass if any check passes; fail if at least one check is
//	               evaluable and none pass; unknown if nothing is evaluable.
//	all:           fail if any evaluable check fails; pass if all evaluable
//	               checks pass (>=1 evaluable); unknown otherwise.
func evalRule(f *facts.Facts, r rules.Rule) Finding {
	fd := Finding{
		RuleID: r.ID, Title: r.Title, Severity: r.Severity,
		Rationale: r.Rationale, Remediation: r.Remediation,
		Tags: r.Tags, Refs: r.Refs,
	}
	all := r.Match == "all"
	joiner := " OR "
	if all {
		joiner = " AND "
	}
	var observed, expected, unknowns []string
	anyEvaluable, anyFail := false, false
	for _, c := range r.Checks {
		res := evalCheck(f, c)
		expected = append(expected, res.expected)
		if res.status == Unknown {
			if res.observed != "" {
				unknowns = append(unknowns, res.observed)
			}
			continue
		}
		anyEvaluable = true
		observed = append(observed, res.observed)
		switch res.status {
		case Pass:
			if !all {
				fd.Status = Pass
				fd.Observed = res.observed
				fd.Expected = res.expected
				return fd
			}
		case Fail:
			anyFail = true
		}
	}
	fd.Expected = strings.Join(expected, joiner)
	switch {
	case !anyEvaluable:
		fd.Status = Unknown
		if len(unknowns) > 0 {
			fd.Observed = strings.Join(dedup(unknowns), "; ")
		} else {
			fd.Observed = "data source unavailable"
		}
	case all && !anyFail:
		fd.Status = Pass
		fd.Observed = strings.Join(dedup(observed), "; ")
	default:
		fd.Status = Fail
		fd.Observed = strings.Join(dedup(observed), "; ")
	}
	return fd
}

type checkResult struct {
	status   Status
	observed string
	expected string
}

func evalCheck(f *facts.Facts, c rules.Check) checkResult {
	switch c.Source {
	case rules.SrcSysctl:
		return evalValue(fmt.Sprintf("sysctl %s", c.Key), lookup(f.Sysctl, c.Key, len(f.Sysctl) > 0), c)
	case rules.SrcKconfig:
		return evalValue(c.Key, lookup(f.Kconfig, c.Key, len(f.Kconfig) > 0), c)
	case rules.SrcCmdline:
		return evalCmdline(f, c)
	case rules.SrcModule:
		return evalModule(f, c)
	case rules.SrcMitigation:
		return evalMitigation(f, c)
	case rules.SrcSecurityFS:
		return evalValue(fmt.Sprintf("securityfs %s", c.Key), lookup(f.SecurityFS, c.Key, len(f.SecurityFS) > 0), c)
	}
	return checkResult{status: Unknown, expected: "unsupported source"}
}

type lookupResult struct {
	value string
	found bool
	// sourceAvailable distinguishes "key missing on this kernel" from
	// "we could not read this data source at all".
	sourceAvailable bool
}

func lookup(m map[string]string, key string, sourceAvailable bool) lookupResult {
	v, ok := m[key]
	return lookupResult{value: v, found: ok, sourceAvailable: sourceAvailable}
}

// evalValue handles map-backed sources (sysctl, kconfig, securityfs).
func evalValue(label string, lr lookupResult, c rules.Check) checkResult {
	expected := describeExpectation(label, c)
	if !lr.sourceAvailable {
		return checkResult{status: Unknown, expected: expected}
	}
	if !lr.found {
		// Key absent. For absent/present ops that is an answer; for
		// value comparisons it means this kernel doesn't have the knob.
		switch c.Op {
		case rules.OpAbsent:
			return checkResult{status: Pass, observed: label + " absent", expected: expected}
		case rules.OpPresent:
			return checkResult{status: Fail, observed: label + " absent", expected: expected}
		default:
			return checkResult{status: Unknown, observed: label + " not present on this kernel", expected: expected}
		}
	}
	return compare(label, lr.value, c, expected)
}

func evalCmdline(f *facts.Facts, c rules.Check) checkResult {
	expected := describeExpectation("cmdline "+c.Key, c)
	if f.CmdlineRaw == "" && len(f.Cmdline) == 0 {
		return checkResult{status: Unknown, expected: expected}
	}
	v, ok := f.Cmdline[c.Key]
	label := fmt.Sprintf("cmdline %s", c.Key)
	switch c.Op {
	case rules.OpAbsent:
		if !ok {
			return checkResult{status: Pass, observed: label + " absent", expected: expected}
		}
		return checkResult{status: Fail, observed: fmt.Sprintf("%s present (=%q)", label, v), expected: expected}
	case rules.OpPresent:
		if ok {
			return checkResult{status: Pass, observed: label + " present", expected: expected}
		}
		return checkResult{status: Fail, observed: label + " absent", expected: expected}
	default:
		if !ok {
			// Parameter not on the cmdline. For not_equals/not_contains
			// that satisfies the intent (the dangerous value is not set).
			switch c.Op {
			case rules.OpNotEquals, rules.OpNotContains:
				return checkResult{status: Pass, observed: label + " absent", expected: expected}
			default:
				return checkResult{status: Fail, observed: label + " absent", expected: expected}
			}
		}
		return compare(label, v, c, expected)
	}
}

func evalModule(f *facts.Facts, c rules.Check) checkResult {
	expected := describeExpectation("module "+c.Key, c)
	if f.Modules == nil {
		return checkResult{status: Unknown, expected: expected}
	}
	loaded := false
	for _, m := range f.Modules {
		if m == c.Key {
			loaded = true
			break
		}
	}
	label := fmt.Sprintf("module %s", c.Key)
	switch c.Op {
	case rules.OpAbsent:
		if !loaded {
			return checkResult{status: Pass, observed: label + " not loaded", expected: expected}
		}
		return checkResult{status: Fail, observed: label + " loaded", expected: expected}
	case rules.OpPresent:
		if loaded {
			return checkResult{status: Pass, observed: label + " loaded", expected: expected}
		}
		return checkResult{status: Fail, observed: label + " not loaded", expected: expected}
	}
	return checkResult{status: Unknown, expected: expected}
}

// evalMitigation with key "*" scans every vulnerability entry; a single
// entry violating the condition fails the check.
func evalMitigation(f *facts.Facts, c rules.Check) checkResult {
	expected := describeExpectation("cpu vulnerabilities", c)
	if len(f.Mitigations) == 0 {
		return checkResult{status: Unknown, expected: expected}
	}
	if c.Key != "*" {
		lr := lookup(f.Mitigations, c.Key, true)
		return evalValue("mitigation "+c.Key, lr, c)
	}
	var bad []string
	names := make([]string, 0, len(f.Mitigations))
	for name := range f.Mitigations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r := compare(name, f.Mitigations[name], c, expected)
		if r.status == Fail {
			bad = append(bad, fmt.Sprintf("%s: %s", name, f.Mitigations[name]))
		}
	}
	if len(bad) == 0 {
		return checkResult{status: Pass, observed: fmt.Sprintf("all %d entries mitigated or not affected", len(names)), expected: expected}
	}
	return checkResult{status: Fail, observed: strings.Join(bad, "; "), expected: expected}
}

func compare(label, observed string, c rules.Check, expected string) checkResult {
	obs := fmt.Sprintf("%s = %q", label, observed)
	pass := false
	switch c.Op {
	case rules.OpEquals:
		pass = observed == c.Value
	case rules.OpNotEquals:
		pass = observed != c.Value
	case rules.OpOneOf:
		for _, v := range c.Values {
			if observed == v {
				pass = true
				break
			}
		}
	case rules.OpContains:
		pass = strings.Contains(observed, c.Value)
	case rules.OpNotContains:
		pass = !strings.Contains(observed, c.Value)
	case rules.OpPresent:
		pass = true // value exists if we got here
	case rules.OpAbsent:
		pass = false
	case rules.OpMin, rules.OpMax:
		o, err1 := firstInt(observed)
		w, err2 := strconv.ParseInt(c.Value, 10, 64)
		if err1 != nil || err2 != nil {
			return checkResult{status: Unknown, observed: obs, expected: expected}
		}
		if c.Op == rules.OpMin {
			pass = o >= w
		} else {
			pass = o <= w
		}
	}
	st := Fail
	if pass {
		st = Pass
	}
	return checkResult{status: st, observed: obs, expected: expected}
}

// firstInt parses the first whitespace-separated token as an integer,
// tolerating multi-value sysctls.
func firstInt(s string) (int64, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty value")
	}
	return strconv.ParseInt(fields[0], 10, 64)
}

func describeExpectation(label string, c rules.Check) string {
	switch c.Op {
	case rules.OpOneOf:
		return fmt.Sprintf("%s in {%s}", label, strings.Join(c.Values, ", "))
	case rules.OpPresent:
		return label + " present"
	case rules.OpAbsent:
		return label + " absent"
	case rules.OpMin:
		return fmt.Sprintf("%s >= %s", label, c.Value)
	case rules.OpMax:
		return fmt.Sprintf("%s <= %s", label, c.Value)
	case rules.OpNotEquals:
		return fmt.Sprintf("%s != %s", label, c.Value)
	case rules.OpContains:
		return fmt.Sprintf("%s contains %q", label, c.Value)
	case rules.OpNotContains:
		return fmt.Sprintf("%s not containing %q", label, c.Value)
	default:
		return fmt.Sprintf("%s = %s", label, c.Value)
	}
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
