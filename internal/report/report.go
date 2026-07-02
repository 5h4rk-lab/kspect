// Package report renders scan and drift results.
//
// Formats:
//   - table: human-readable terminal output (color only on a TTY / --color)
//   - json:  stable machine-readable schema for pipelines and SIEM ingestion
//   - sarif: SARIF 2.1.0, uploadable to GitHub code scanning so kernel
//     posture failures appear alongside application findings
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/5h4rk-lab/kspect/internal/baseline"
	"github.com/5h4rk-lab/kspect/internal/engine"
	"github.com/5h4rk-lab/kspect/internal/rules"
)

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiGray   = "\033[90m"
	ansiBold   = "\033[1m"
)

// Options controls rendering.
type Options struct {
	Color    bool
	ShowPass bool // include passing rules in table output
	Version  string
}

// WriteTable renders a human-readable report.
func WriteTable(w io.Writer, rep *engine.Report, o Options) {
	c := colorizer(o.Color)
	fmt.Fprintf(w, "%skspect scan%s — kernel %s (%s)\n\n",
		c(ansiBold), c(ansiReset), rep.Kernel.Release, rep.Kernel.Arch)

	for _, f := range rep.Findings {
		if f.Status == engine.Pass && !o.ShowPass {
			continue
		}
		var mark, color string
		switch {
		case f.Status == engine.Fail && f.Severity == rules.SevInfo:
			// Advisory rules: a "failing" info rule is a suggestion,
			// not a defect — rendering it as FAIL erodes trust.
			mark, color = "NOTE", ansiYellow
		case f.Status == engine.Fail:
			mark, color = "FAIL", ansiRed
		case f.Status == engine.Pass:
			mark, color = "PASS", ansiGreen
		default:
			mark, color = "?   ", ansiGray
		}
		fmt.Fprintf(w, "%s%-4s%s %-7s %-20s %s\n",
			c(color), mark, c(ansiReset), strings.ToUpper(string(f.Severity)), f.RuleID, f.Title)
		if f.Status != engine.Pass {
			fmt.Fprintf(w, "     %sobserved:%s %s\n", c(ansiGray), c(ansiReset), f.Observed)
			fmt.Fprintf(w, "     %sexpected:%s %s\n", c(ansiGray), c(ansiReset), f.Expected)
			if f.Status == engine.Fail && f.Remediation != "" {
				fmt.Fprintf(w, "     %sfix:%s      %s\n", c(ansiGray), c(ansiReset), f.Remediation)
			}
		}
	}

	s := rep.Summary
	fmt.Fprintf(w, "\n%sSummary:%s %d checks — %s%d fail%s, %d pass, %d unknown",
		c(ansiBold), c(ansiReset), s.Total, c(ansiRed), s.Fail, c(ansiReset), s.Pass, s.Unknown)
	if s.Fail > 0 {
		var parts []string
		for _, sev := range []rules.Severity{rules.SevHigh, rules.SevMedium, rules.SevLow, rules.SevInfo} {
			if n := s.FailBySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, sev))
			}
		}
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)
}

// WriteJSON renders the scan report as indented JSON.
func WriteJSON(w io.Writer, rep *engine.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ---- SARIF 2.1.0 ----

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription"`
	Help             sarifText         `json:"help"`
	Properties       map[string]any    `json:"properties,omitempty"`
	DefaultConfig    *sarifRuleDefault `json:"defaultConfiguration,omitempty"`
}
type sarifRuleDefault struct {
	Level string `json:"level"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}

func sarifLevel(sev rules.Severity) string {
	switch sev {
	case rules.SevHigh:
		return "error"
	case rules.SevMedium, rules.SevLow:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF emits failing findings as SARIF results (passes and unknowns
// are omitted; code scanning is for actionable problems).
func WriteSARIF(w io.Writer, rep *engine.Report, o Options) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "kspect",
			InformationURI: "https://github.com/5h4rk-lab/kspect",
			Version:        o.Version,
		}},
		Results: []sarifResult{},
	}
	seenRule := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Status != engine.Fail {
			continue
		}
		if !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Rationale},
				Help:             sarifText{Text: f.Remediation},
				Properties:       map[string]any{"tags": f.Tags, "severity": string(f.Severity)},
				DefaultConfig:    &sarifRuleDefault{Level: sarifLevel(f.Severity)},
			})
		}
		run.Results = append(run.Results, sarifResult{
			RuleID: f.RuleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifText{Text: fmt.Sprintf("%s — observed: %s; expected: %s. Fix: %s",
				f.Title, f.Observed, f.Expected, f.Remediation)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: "kernel/" + f.RuleID},
				},
			}},
		})
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteDriftTable renders drift results for humans.
func WriteDriftTable(w io.Writer, d *baseline.Drift, o Options) {
	c := colorizer(o.Color)
	if !d.HasDrift() {
		fmt.Fprintf(w, "%sNo drift%s — current state matches baseline (%s)\n",
			c(ansiGreen), c(ansiReset), d.BaselineAt)
		return
	}
	fmt.Fprintf(w, "%sDrift detected%s: %d change(s) since baseline %s\n\n",
		c(ansiRed), c(ansiReset), len(d.Changes), d.BaselineAt)
	for _, ch := range d.Changes {
		switch ch.Type {
		case "changed":
			fmt.Fprintf(w, "  ~ %-10s %-45s %q -> %q\n", ch.Kind, ch.Key, ch.Old, ch.New)
		case "added":
			fmt.Fprintf(w, "  + %-10s %-45s %q\n", ch.Kind, ch.Key, ch.New)
		case "removed":
			fmt.Fprintf(w, "  - %-10s %-45s (was %q)\n", ch.Kind, ch.Key, ch.Old)
		}
	}
}

// WriteDriftJSON renders drift results as JSON.
func WriteDriftJSON(w io.Writer, d *baseline.Drift) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

func colorizer(enabled bool) func(string) string {
	if enabled {
		return func(s string) string { return s }
	}
	return func(string) string { return "" }
}
